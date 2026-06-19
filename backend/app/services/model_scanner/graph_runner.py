import json
import re
import tempfile
import time
import uuid
from pathlib import Path
from typing import TypedDict

import requests
from langgraph.graph import END, StateGraph

from app.config import settings
from app.services.model_scanner.static_analyzer import analyze_file, detect_language
from app.services.model_scanner.semantic_chunker import CHUNKER_VERSION, generate_semantic_chunks, syntax_check


class AnalyzerState(TypedDict, total=False):
    file_path: str
    file_name: str
    original_code: str
    language: str
    static_findings: str
    system_prompt: str
    cwe_model_response: str
    code_model_response: str
    vulnerabilities: list[dict]
    corrected_code: str
    confidence_score: float
    missing_cwes: list[str]
    missing_findings: str
    corrected_code_findings: str
    corrected_code_is_clean: bool
    code_retry_count: int
    model_response: str
    error: str


MODEL_NAME = getattr(settings, "security_model_name", "quen_fine_tuned")
MODEL_PASS_TIMEOUT_SECONDS = int(getattr(settings, "security_model_timeout_seconds", 300))
GROQ_RATE_LIMIT_RETRY_SECONDS = 120
MAX_CHUNK_LINES = 70
CACHE_ROOT = Path(tempfile.gettempdir()) / "secureguard_chunks"


class SyntaxValidationError(Exception):
    """Raised when user code cannot be scanned because it has syntax errors."""


def _chat_url() -> str:
    base_url = (getattr(settings, "security_model_base_url", "") or "").strip()
    if not base_url:
        return ""
    return f"{base_url.rstrip('/')}/chat/completions"


def extract_json_object(text: str) -> dict:
    cleaned = text.strip()
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", cleaned, re.DOTALL)
    if fenced:
        cleaned = fenced.group(1)
    else:
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start != -1 and end != -1 and end > start:
            cleaned = cleaned[start : end + 1]
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        return {}


def extract_partial_json_string(text: str, key: str) -> str:
    """Decode a JSON string value while its closing quote may not exist yet."""
    match = re.search(rf'"{re.escape(key)}"\s*:\s*"', text)
    if not match:
        return ""
    value = text[match.end():]
    escaped = False
    output: list[str] = []
    escape_map = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "\\": "\\", "/": "/"}
    index = 0
    while index < len(value):
        char = value[index]
        if escaped:
            if char == "u" and index + 4 < len(value):
                codepoint = value[index + 1:index + 5]
                try:
                    output.append(chr(int(codepoint, 16)))
                    index += 4
                except ValueError:
                    pass
            else:
                output.append(escape_map.get(char, char))
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"':
            break
        else:
            output.append(char)
        index += 1
    return "".join(output)


def first_sentence(text: str) -> str:
    text = " ".join(str(text or "").split())
    if not text:
        return "Static analysis reported this issue."
    stops = [idx for idx in (text.find("."), text.find(";")) if idx != -1]
    return text if not stops else text[: min(stops) + 1]


def split_findings(findings: str) -> list[str]:
    blocks = re.split(r"\n\s*\n", findings.strip())
    return [block.strip() for block in blocks if block.strip().startswith("finding_")]


def filter_findings_for_range(findings: str, start_line: int, end_line: int) -> str:
    selected = []
    for block in split_findings(findings):
        line_number = _line_number_from_finding(block)
        if start_line <= line_number <= end_line:
            selected.append(block)
    return "\n\n".join(selected) if selected else "findings: No static findings in this chunk"


def source_slice(source_code: str, start_line: int, end_line: int) -> str:
    lines = source_code.splitlines()
    return "\n".join(lines[max(0, start_line - 1):end_line])


def normalize_source_newlines(source_code: str) -> str:
    """Normalize newline encodings without turning CR artifacts into blank source lines."""
    return re.sub(r"\r+\n", "\n", source_code).replace("\r", "\n")


def _canonical_source_for_duplicate_check(source_code: str) -> str:
    normalized = normalize_source_newlines(source_code).strip()
    lines = [" ".join(line.rstrip().split()) for line in normalized.split("\n")]
    return "\n".join(lines).strip()


def deduplicate_repeated_source(source_code: str) -> str:
    """Collapse accidental full-file duplication before syntax/chunking.

    Some upload flows can concatenate the same selected file twice, sometimes
    without a newline between copies. This guard only removes the duplicate
    when both halves are the same whole source after harmless whitespace
    normalization.
    """
    normalized = normalize_source_newlines(source_code)
    if not normalized.strip():
        return source_code

    first_line = next((line for line in normalized.split("\n") if line.strip()), "")
    if not first_line:
        return source_code

    search_from = normalized.find(first_line) + len(first_line)
    while True:
        duplicate_start = normalized.find(first_line, search_from)
        if duplicate_start == -1:
            break
        left = normalized[:duplicate_start]
        right = normalized[duplicate_start:]
        if _canonical_source_for_duplicate_check(left) == _canonical_source_for_duplicate_check(right):
            return right if source_code.endswith("\n") else right.rstrip("\n")
        search_from = duplicate_start + len(first_line)

    lines = normalized.splitlines()
    if len(lines) % 2 == 0:
        midpoint = len(lines) // 2
        left = "\n".join(lines[:midpoint])
        right = "\n".join(lines[midpoint:])
        if _canonical_source_for_duplicate_check(left) == _canonical_source_for_duplicate_check(right):
            return left + ("\n" if source_code.endswith("\n") else "")

    return source_code


def cache_chunks(file_name: str, chunks: list[dict]) -> Path:
    CACHE_ROOT.mkdir(parents=True, exist_ok=True)
    cache_path = CACHE_ROOT / f"{Path(file_name).stem}-{uuid.uuid4().hex}.json"
    cache_path.write_text(json.dumps(chunks, ensure_ascii=False, indent=2), encoding="utf-8")
    return cache_path


def build_chunks(file_path: Path, file_name: str, source_code: str) -> list[dict]:
    chunk_result = generate_semantic_chunks(file_path, validate_syntax=False)
    chunks = chunk_result["chunks"] or []
    source_line_count = int(chunk_result.get("source_line_count") or max(1, len(source_code.splitlines())))
    chunker_version = str(chunk_result.get("chunker_version") or CHUNKER_VERSION)
    for chunk in chunks:
        chunk["source_line_count"] = source_line_count
        chunk["chunker_version"] = chunker_version
        content = str(chunk.get("content") or "")
        if len(content.splitlines()) > MAX_CHUNK_LINES:
            raise RuntimeError(
                f"Semantic chunk exceeded {MAX_CHUNK_LINES} lines: "
                f"{chunk.get('name')} lines {chunk.get('start_line')}-{chunk.get('end_line')}"
            )
    if not chunks:
        total_lines = max(1, source_code.count("\n") + 1)
        chunks = [
            {
                "index": 1,
                "kind": "file",
                "name": file_name,
                "start_line": 1,
                "end_line": min(total_lines, MAX_CHUNK_LINES),
                "content": source_slice(source_code, 1, min(total_lines, MAX_CHUNK_LINES)),
                "display_code": source_slice(source_code, 1, min(total_lines, MAX_CHUNK_LINES)),
                "source_line_count": total_lines,
                "chunker_version": chunker_version,
            }
        ]
    return chunks


def cwes_from_text(text: str) -> set[str]:
    return set(re.findall(r"CWE-\d+", text))


def expected_cwes_from_findings(findings: str) -> set[str]:
    expected: set[str] = set()
    for block in split_findings(findings):
        expected.update(cwes_from_text(block))
    return expected


def _line_number_from_finding(block: str) -> int:
    match = re.search(r"vul_line_location:\s*line:\s*(\d+)", block)
    return int(match.group(1)) if match else 0


def _int_from_value(value, default: int = 0) -> int:
    if isinstance(value, int):
        return value
    match = re.search(r"\d+", str(value or ""))
    return int(match.group(0)) if match else default


def cwe_evidence_map(findings: str) -> dict[str, dict]:
    evidence: dict[str, dict] = {}
    for block in split_findings(findings):
        reason = ""
        location = ""
        detected_line = ""
        for line in block.splitlines():
            stripped = line.strip()
            if stripped.startswith("reason:"):
                reason = stripped.removeprefix("reason:").strip()
            elif stripped.startswith("vul_line_location:"):
                location = stripped.removeprefix("vul_line_location:").strip()
            elif stripped.startswith("vul_detected_line:"):
                detected_line = stripped.removeprefix("vul_detected_line:").strip()
        for cwe in cwes_from_text(block):
            evidence.setdefault(
                cwe,
                {
                    "location": location,
                    "line_number": _line_number_from_finding(block),
                    "affected_code": detected_line,
                    "description": first_sentence(reason),
                },
            )
    return evidence


def severity_from_location(location: str) -> str:
    lowered = location.lower()
    if "critical" in lowered:
        return "Critical"
    if "high" in lowered:
        return "High"
    if "moderate" in lowered or "medium" in lowered:
        return "Medium"
    return "Low"


def normalize_severity(value: str, fallback: str = "Low") -> str:
    lowered = str(value or "").strip().lower()
    if lowered == "critical":
        return "Critical"
    if lowered == "high":
        return "High"
    if lowered in {"moderate", "medium"}:
        return "Medium"
    if lowered == "low":
        return "Low"
    return fallback


def vulnerability_key(vulnerability: dict) -> tuple[str, int, str]:
    cwe_id = str(vulnerability.get("cwe_id", "")).strip().upper()
    line_number = _int_from_value(vulnerability.get("absolute_line") or vulnerability.get("line_number"))
    affected_code = " ".join(str(vulnerability.get("affected_code", "")).strip().split()).lower()
    return cwe_id, line_number, affected_code


def merge_unique_vulnerabilities(*groups: list[dict]) -> list[dict]:
    merged: list[dict] = []
    seen: set[tuple[str, int, str]] = set()
    for group in groups:
        for vulnerability in group:
            key = vulnerability_key(vulnerability)
            if key in seen:
                continue
            seen.add(key)
            merged.append(vulnerability)
    return merged


def vulnerabilities_from_static_findings(findings: str, state: AnalyzerState, chunk: dict | None = None) -> list[dict]:
    vulnerabilities: list[dict] = []
    for block in split_findings(findings):
        reason = ""
        location = ""
        detected_line = ""
        for line in block.splitlines():
            stripped = line.strip()
            if stripped.startswith("reason:"):
                reason = stripped.removeprefix("reason:").strip()
            elif stripped.startswith("vul_line_location:"):
                location = stripped.removeprefix("vul_line_location:").strip()
            elif stripped.startswith("vul_detected_line:"):
                detected_line = stripped.removeprefix("vul_detected_line:").strip()

        line_number = _line_number_from_finding(block)
        cwe_ids = sorted(cwes_from_text(block)) or ["CWE-Unknown"]
        for cwe_id in cwe_ids:
            vulnerabilities.append(
                {
                    "cwe_id": cwe_id,
                    "cwe_name": cwe_id,
                    "severity": severity_from_location(location),
                    "line_number": line_number,
                    "absolute_line": line_number,
                    "location": location or (
                        f"lines {chunk.get('start_line')}-{chunk.get('end_line')}" if chunk else ""
                    ),
                    "description": first_sentence(reason),
                    "fix_suggestion": "Apply bounds checks, validate input, and replace unsafe calls with safer alternatives.",
                    "affected_code": detected_line,
                    "function_name": chunk.get("name", "") if chunk else "",
                    "file_path": state.get("file_name", ""),
                    **(
                        {
                            "chunk_index": chunk.get("index"),
                            "chunk_name": chunk.get("name", ""),
                            "chunk_start_line": chunk.get("start_line", 0),
                            "chunk_end_line": chunk.get("end_line", 0),
                        }
                        if chunk
                        else {}
                    ),
                }
            )
    return merge_unique_vulnerabilities(vulnerabilities)


def normalize_vulnerabilities(raw: list, state: AnalyzerState) -> list[dict]:
    expected = expected_cwes_from_findings(state["static_findings"])
    evidence = cwe_evidence_map(state["static_findings"])
    normalized = []
    seen = set()
    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, dict):
            continue
        cwe_id = str(item.get("cwe_id", "")).strip()
        if cwe_id not in expected or cwe_id in seen:
            continue
        seen.add(cwe_id)
        ev = evidence.get(cwe_id, {})
        normalized.append(
            {
                "cwe_id": cwe_id,
                "cwe_name": str(item.get("cwe_name", "")).strip() or cwe_id,
                "severity": normalize_severity(item.get("severity"), severity_from_location(ev.get("location", ""))),
                "line_number": _int_from_value(item.get("line_number") or ev.get("line_number") or 0),
                "absolute_line": _int_from_value(item.get("line_number") or ev.get("line_number") or 0),
                "location": str(item.get("location", "")).strip() or ev.get("location", ""),
                "description": first_sentence(item.get("description") or item.get("explanation") or ev.get("description")),
                "fix_suggestion": first_sentence(item.get("fix_suggestion") or item.get("recommended_fix") or "Apply bounds checks, validate input, and replace unsafe calls with safer alternatives."),
                "affected_code": str(item.get("affected_code", "")).strip() or ev.get("affected_code", ""),
                "function_name": str(item.get("function_name", "")).strip(),
                "file_path": state.get("file_name", ""),
            }
        )
    return normalized


def normalize_chunk_vulnerabilities(raw: list, state: AnalyzerState, chunk: dict) -> list[dict]:
    evidence = cwe_evidence_map(state["static_findings"])
    normalized = []
    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, dict):
            continue
        cwe_id = str(item.get("cwe_id", "")).strip()
        if not cwe_id:
            continue
        line_number = _int_from_value(
            item.get("line_number")
            or item.get("absolute_line")
            or item.get("vul_line_number")
            or chunk.get("start_line")
            or 0
        )
        ev = evidence.get(cwe_id, {})
        normalized.append(
            {
                "cwe_id": cwe_id,
                "cwe_name": str(item.get("cwe_name", "")).strip() or cwe_id,
                "severity": normalize_severity(item.get("severity") or item.get("type"), severity_from_location(ev.get("location", ""))),
                "line_number": line_number,
                "absolute_line": line_number,
                "location": str(item.get("location", "")).strip() or ev.get("location", "") or f"lines {chunk.get('start_line')}-{chunk.get('end_line')}",
                "description": first_sentence(item.get("description") or item.get("explanation") or ev.get("description")),
                "fix_suggestion": first_sentence(item.get("fix_suggestion") or item.get("recommended_fix") or "Apply bounds checks, validate input, and replace unsafe calls with safer alternatives."),
                "affected_code": str(item.get("affected_code") or item.get("vul_detected_line") or "").strip() or ev.get("affected_code", ""),
                "function_name": str(item.get("function_name", "")).strip() or chunk.get("name", ""),
                "file_path": state.get("file_name", ""),
                "chunk_index": chunk.get("index"),
                "chunk_name": chunk.get("name", ""),
                "chunk_start_line": chunk.get("start_line", 0),
                "chunk_end_line": chunk.get("end_line", 0),
            }
        )
    return normalized


def coverage(findings: str, vulnerabilities: list[dict]) -> tuple[float, list[str], str]:
    expected = expected_cwes_from_findings(findings)
    present = {item.get("cwe_id", "") for item in vulnerabilities}
    missing = sorted(expected.difference(present))
    score = 100.0 if not expected else (len(expected.intersection(present)) / len(expected)) * 100
    missing_blocks = [block for block in split_findings(findings) if cwes_from_text(block).intersection(missing)]
    return score, missing, "\n\n".join(missing_blocks)


def iter_model_response(system_prompt: str, user_prompt: str, required_key: str | None = None):
    payload = {
        "model": MODEL_NAME,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.3,
        "top_p": 1.0,
        "repeat_penalty": 1.05,
        "max_tokens": 2048,
        "stream": True,
    }

    groq_base = (getattr(settings, "groq_base_url", "") or "").strip()
    groq_key = (getattr(settings, "groq_api_key", "") or "").strip()
    has_groq_fallback = bool(groq_base and groq_key)

    # Try primary configured model endpoint first. If it fails and Groq is
    # configured, this is a normal fallback path, not a scan-ending error.
    primary_url = _chat_url()
    primary_error = "Security model endpoint is not configured."
    if primary_url:
        try:
            print(f"[model_scanner] primary endpoint attempt: url={primary_url} model={MODEL_NAME}")
            started_at = time.monotonic()
            response = requests.post(
                primary_url,
                json=payload,
                timeout=(10, MODEL_PASS_TIMEOUT_SECONDS),
                headers={"ngrok-skip-browser-warning": "true"},
                stream=True,
            )
            if time.monotonic() - started_at > MODEL_PASS_TIMEOUT_SECONDS:
                primary_error = "Request timeout exceeded. Please try again."
                print(f"[model_scanner] primary endpoint fallback: timeout url={primary_url}")
            elif response.status_code != 200:
                primary_error = f"Model API error: {response.status_code} - {response.text}"
                print(f"[model_scanner] primary endpoint fallback: status={response.status_code} url={primary_url}")
            else:
                content_parts: list[str] = []
                # The requests default is a 512-byte read buffer. LM Studio emits
                # small SSE frames, so that default hides tokens for a long time.
                for raw_line in response.iter_lines(chunk_size=1, decode_unicode=True):
                    line = (raw_line or "").strip()
                    if not line:
                        continue
                    if line.startswith("data:"):
                        line = line[5:].strip()
                    if line == "[DONE]":
                        break
                    try:
                        data = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    choices = data.get("choices") or []
                    if not choices:
                        continue
                    delta = choices[0].get("delta", {}).get("content")
                    if delta is None:
                        delta = choices[0].get("message", {}).get("content")
                    if delta:
                        content_parts.append(delta)
                        yield {"event": "model_delta", "text": delta}
                content = "".join(content_parts)
                parsed_content = extract_json_object(content) if required_key else {}
                if content and (not required_key or required_key in parsed_content):
                    print(f"[model_scanner] primary endpoint success: url={primary_url} model={MODEL_NAME}")
                    return content, ""
                primary_error = (
                    f"Security model returned invalid JSON without '{required_key}'."
                    if content and required_key
                    else "Security model returned an empty response."
                )
                print(f"[model_scanner] primary endpoint fallback: invalid response url={primary_url}")
        except requests.Timeout:
            primary_error = "Request timeout exceeded. Please try again."
            print(f"[model_scanner] primary endpoint fallback: timeout url={primary_url}")
        except Exception as exc:
            primary_error = f"Model request failed: {exc}"
            print(f"[model_scanner] primary endpoint fallback: exception={exc}")
    elif has_groq_fallback:
        print("[model_scanner] primary endpoint not configured; using Groq fallback")

    # Primary failed — attempt Groq fallback if configured
    if groq_base and groq_key:
        groq_url = f"{groq_base.rstrip('/')}/chat/completions"
        groq_model = (getattr(settings, "groq_model_name", "meta-llama/llama-4-scout-17b-16e-instruct") or "meta-llama/llama-4-scout-17b-16e-instruct").strip()
        headers = {"Authorization": f"Bearer {groq_key}"}
        groq_payload = {**payload, "model": groq_model, "stream": True}
        groq_payload.pop("repeat_penalty", None)
        for attempt in range(2):
            try:
                started_at = time.monotonic()
                response = requests.post(
                    groq_url,
                    json=groq_payload,
                    timeout=(10, MODEL_PASS_TIMEOUT_SECONDS),
                    headers=headers,
                    stream=True,
                )
                if time.monotonic() - started_at > MODEL_PASS_TIMEOUT_SECONDS:
                    print(f"[model_scanner] groq timeout: model={groq_model}")
                    return "", "Request timeout exceeded. Please try again."
                if response.status_code == 429 and attempt == 0:
                    retry_after = response.headers.get("Retry-After")
                    try:
                        retry_seconds = max(GROQ_RATE_LIMIT_RETRY_SECONDS, int(float(retry_after or 0)))
                    except ValueError:
                        retry_seconds = GROQ_RATE_LIMIT_RETRY_SECONDS
                    print(
                        f"[model_scanner] groq rate limit: waiting {retry_seconds}s before retry "
                        f"model={groq_model} body={response.text[:300]}"
                    )
                    time.sleep(retry_seconds)
                    continue
                if response.status_code != 200:
                    print(f"[model_scanner] groq error: status={response.status_code} model={groq_model} body={response.text[:300]}")
                    return "", f"GROQ API error: {response.status_code} - {response.text}"
                content_parts: list[str] = []
                for raw_line in response.iter_lines(chunk_size=1, decode_unicode=True):
                    line = (raw_line or "").strip()
                    if not line:
                        continue
                    if line.startswith("data:"):
                        line = line[5:].strip()
                    if line == "[DONE]":
                        break
                    try:
                        data = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    choices = data.get("choices") or []
                    if not choices:
                        continue
                    delta = choices[0].get("delta", {}).get("content")
                    if delta:
                        content_parts.append(delta)
                        yield {"event": "model_delta", "text": delta}
                content = "".join(content_parts)
                parsed_content = extract_json_object(content) if required_key else {}
                if content and (not required_key or required_key in parsed_content):
                    print(f"[model_scanner] groq success: model={groq_model}")
                    return content, ""
                if content and required_key:
                    print(f"[model_scanner] groq invalid response: missing={required_key} model={groq_model}")
                    return "", f"GROQ API returned invalid JSON without '{required_key}'."
                print(f"[model_scanner] groq empty response: model={groq_model}")
                return "", "GROQ API returned an empty response."
            except requests.Timeout:
                print(f"[model_scanner] groq timeout: model={groq_model}")
                return "", "Request timeout exceeded. Please try again."
            except Exception as exc:
                print(f"[model_scanner] groq exception: {exc}")
                return "", f"GROQ request failed: {exc}"

    # No fallback available — return primary error
    return "", primary_error


def call_model(system_prompt: str, user_prompt: str) -> tuple[str, str]:
    stream = iter_model_response(system_prompt, user_prompt)
    while True:
        try:
            next(stream)
        except StopIteration as done:
            return done.value or ("", "Security model did not return a response.")


def analyze_chunk_with_model(state: AnalyzerState, chunk: dict, total_chunks: int) -> tuple[list[dict], str]:
    response = ""
    error = ""
    for event in iter_analyze_chunk_with_model_events(state, chunk, total_chunks):
        if event.get("event") == "_chunk_analysis_complete":
            response = event.get("response", "")
            error = event.get("error", "")
            break
    if error:
        if "timeout" in error.lower():
            raise TimeoutError(error)
        raise RuntimeError(error)
    parsed = extract_json_object(response)
    chunk_findings = filter_findings_for_range(state["static_findings"], chunk["start_line"], chunk["end_line"])
    static_vulnerabilities = vulnerabilities_from_static_findings(chunk_findings, state, chunk)
    model_vulnerabilities = normalize_chunk_vulnerabilities(parsed.get("vulnerabilities", []), state, chunk)
    return merge_unique_vulnerabilities(static_vulnerabilities, model_vulnerabilities), f"Reviewed lines {chunk['start_line']}-{chunk['end_line']}"


def iter_analyze_chunk_with_model_events(state: AnalyzerState, chunk: dict, total_chunks: int):
    chunk_findings = filter_findings_for_range(state["static_findings"], chunk["start_line"], chunk["end_line"])
    system_prompt = f"""# Role
You review one C/C++ source chunk for security vulnerabilities.

# Rules
- You have two inputs: static analyzer findings and one source chunk.
- Include vulnerabilities supported by the findings.
- Also include real vulnerabilities you discover in the chunk.
- Remove duplicates.
- Return JSON only. No markdown.

# Static Analyzer Findings For This Chunk
{chunk_findings}

# Required JSON Schema
{{
  "vulnerabilities": [
    {{
      "cwe_id": "CWE-XXX",
      "severity": "Critical|High|Medium|Low",
      "line_number": 1,
      "affected_code": "exact vulnerable code",
      "description": "one sentence explanation",
      "fix_suggestion": "one sentence fix"
    }}
  ]
}}
"""
    user_prompt = f"Review chunk {chunk['index']} of {total_chunks}: lines {chunk['start_line']}-{chunk['end_line']}.\n\n```{state['language'].lower()}\n{chunk['content']}\n```"
    stream = iter_model_response(system_prompt, user_prompt, required_key="vulnerabilities")
    while True:
        try:
            event = next(stream)
            if event.get("event") == "model_delta":
                yield {
                    "event": "model_delta",
                    "file_path": state.get("file_name"),
                    "chunk_index": chunk["index"],
                    "text": event.get("text", ""),
                }
        except StopIteration as done:
            response, error = done.value or ("", "Security model did not return a response.")
            yield {"event": "_chunk_analysis_complete", "response": response, "error": error}
            return


def generate_corrected_code_for_file(state: AnalyzerState, vulnerabilities: list[dict], source_code: str | None = None) -> tuple[str, str]:
    code = source_code if source_code is not None else state["original_code"]
    response, error = call_model(
        prepare_code_prompt({**state, "vulnerabilities": vulnerabilities}),
        f"Generate corrected {state['language']} source code. Ensure none of the listed CWE issues remain:\n\n```{state['language'].lower()}\n{code}\n```",
    )
    if error:
        if "timeout" in error.lower():
            raise TimeoutError(error)
        raise RuntimeError(error)
    corrected_code = extract_json_object(response).get("corrected_code", "")
    if not corrected_code:
        print("[model_scanner] corrected code missing: using original source fallback")
        return code, response
    return corrected_code, response


def iter_corrected_code_events(state: AnalyzerState, vulnerabilities: list[dict], source_code: str):
    stream = iter_model_response(
        prepare_code_prompt({**state, "vulnerabilities": vulnerabilities}),
        f"Generate corrected {state['language']} source code. Ensure none of the listed CWE issues remain:\n\n```{state['language'].lower()}\n{source_code}\n```",
        required_key="corrected_code",
    )
    response = ""
    last_snapshot = ""
    while True:
        try:
            event = next(stream)
            if event.get("event") != "model_delta":
                continue
            response += event.get("text", "")
            snapshot = extract_partial_json_string(response, "corrected_code")
            if snapshot != last_snapshot:
                last_snapshot = snapshot
                yield {"event": "correction_delta", "corrected_code": snapshot}
        except StopIteration as done:
            final_response, error = done.value or ("", "Security model did not return a response.")
            corrected_code = extract_json_object(final_response).get("corrected_code", "")
            yield {
                "event": "_correction_complete",
                "corrected_code": corrected_code or source_code,
                "response": final_response,
                "error": error,
            }
            return


def static_analyzer_node(state: AnalyzerState) -> AnalyzerState:
    findings = analyze_file(state["file_path"])
    original_code = Path(state["file_path"]).read_text(encoding="utf-8", errors="replace")
    return {
        **state,
        "static_findings": findings,
        "original_code": original_code,
        "language": detect_language(state["file_path"]),
    }


def prepare_detect_prompt_node(state: AnalyzerState) -> AnalyzerState:
    system_prompt = f"""# Role
You identify C/C++ vulnerability CWEs from static-analysis evidence.

# Rules
- Use only CWE IDs supported by the static-analysis findings.
- Each finding must include severity, line_number, description, fix_suggestion, and affected_code when available.
- Return JSON only. No markdown.

# Static Analysis Findings
{state["static_findings"]}

# Required JSON Schema
{{
  "language": "C or CPP",
  "is_vulnerable": true,
  "vulnerabilities": [
    {{
      "cwe_id": "CWE-XXX",
      "cwe_name": "name of cwe",
      "severity": "Critical|High|Medium|Low",
      "line_number": 1,
      "description": "What is wrong",
      "fix_suggestion": "How to fix it",
      "affected_code": "line of code"
    }}
  ]
}}
"""
    return {**state, "system_prompt": system_prompt}


def model_detect_cwes_node(state: AnalyzerState) -> AnalyzerState:
    response, error = call_model(
        state["system_prompt"],
        f"Analyze this {state['language']} code and return vulnerability JSON only:\n\n```{state['language'].lower()}\n{state['original_code']}\n```",
    )
    if error:
        return {**state, "cwe_model_response": "", "error": error}
    return {**state, "cwe_model_response": response}


def validate_cwes_node(state: AnalyzerState) -> AnalyzerState:
    response_json = extract_json_object(state.get("cwe_model_response", ""))
    static_vulnerabilities = vulnerabilities_from_static_findings(state["static_findings"], state)
    model_vulnerabilities = normalize_vulnerabilities(response_json.get("vulnerabilities", []), state)
    vulnerabilities = merge_unique_vulnerabilities(static_vulnerabilities, model_vulnerabilities)
    score, missing, missing_findings = coverage(state["static_findings"], vulnerabilities)
    return {
        **state,
        "vulnerabilities": vulnerabilities,
        "confidence_score": score,
        "missing_cwes": missing,
        "missing_findings": missing_findings,
    }


def should_continue_detection(state: AnalyzerState) -> str:
    if state.get("error"):
        return "error"
    return "continue"


def prepare_code_prompt(state: AnalyzerState, retry: bool = False) -> str:
    retry_section = f"\n# Analyzer Findings From Previous corrected_code\n{state.get('corrected_code_findings', '')}\n" if retry else ""
    return f"""# Role
You generate secure corrected C/C++ code.

# Rules
- Return only corrected_code JSON. Do not return CWE objects.
- Fix every vulnerability listed below.
- Avoid introducing new static-analyzer findings.
- Return JSON only. No markdown.

# Vulnerability Memory
{json.dumps(state.get("vulnerabilities", []), indent=2)}

# Static Analysis Findings
{state["static_findings"]}
{retry_section}
# Required JSON Schema
{{ "corrected_code": "Full secure corrected code" }}
"""


def model_generate_corrected_code_node(state: AnalyzerState) -> AnalyzerState:
    response, error = call_model(
        prepare_code_prompt(state),
        f"Generate corrected {state['language']} code for:\n\n```{state['language'].lower()}\n{state['original_code']}\n```",
    )
    if error:
        return {**state, "code_model_response": "", "corrected_code": "None", "error": error}
    corrected_code = extract_json_object(response).get("corrected_code", "")
    if not corrected_code:
        return {
            **state,
            "code_model_response": response,
            "corrected_code": "None",
            "error": "Security model did not return corrected code.",
        }
    return {**state, "code_model_response": response, "corrected_code": corrected_code}


def analyze_corrected_code_node(state: AnalyzerState) -> AnalyzerState:
    corrected_code = state.get("corrected_code", "")
    if not corrected_code or corrected_code == "None":
        return {**state, "corrected_code_findings": "findings: corrected_code missing", "corrected_code_is_clean": False}
    suffix = ".cpp" if state["language"] == "CPP" else ".c"
    with tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False, encoding="utf-8") as handle:
        handle.write(corrected_code)
        candidate = handle.name
    findings = analyze_file(candidate)
    Path(candidate).unlink(missing_ok=True)
    return {**state, "corrected_code_findings": findings, "corrected_code_is_clean": findings.strip() == "findings: Code is safe"}


def should_retry_code(state: AnalyzerState) -> str:
    if state.get("code_retry_count", 0) > 0:
        return "skip"
    return "retry" if not state.get("corrected_code_is_clean", True) else "skip"


def retry_corrected_code_node(state: AnalyzerState) -> AnalyzerState:
    response, error = call_model(
        prepare_code_prompt(state, retry=True),
        f"Return corrected {state['language']} code only, fixing the analyzer findings from the previous corrected_code.",
    )
    if error:
        return {**state, "code_retry_count": 1, "error": error}
    corrected_code = extract_json_object(response).get("corrected_code", "")
    return {**state, "corrected_code": corrected_code or state.get("corrected_code", "None"), "code_retry_count": 1}


def finalize_node(state: AnalyzerState) -> AnalyzerState:
    if state.get("error"):
        return state
    final_json = {
        "language": "C++" if state.get("language") == "CPP" else "C",
        "is_vulnerable": bool(state.get("vulnerabilities")),
        "vulnerabilities": state.get("vulnerabilities", []),
        "corrected_code": state.get("corrected_code") or "None",
        "static_findings": state.get("static_findings", ""),
        "corrected_code_is_clean": state.get("corrected_code_is_clean", False),
    }
    return {**state, "model_response": json.dumps(final_json, ensure_ascii=False)}


def build_graph():
    graph = StateGraph(AnalyzerState)
    graph.add_node("static_analyzer", static_analyzer_node)
    graph.add_node("prepare_detect_prompt", prepare_detect_prompt_node)
    graph.add_node("model_detect_cwes", model_detect_cwes_node)
    graph.add_node("validate_cwes", validate_cwes_node)
    graph.add_node("model_generate_corrected_code", model_generate_corrected_code_node)
    graph.add_node("analyze_corrected_code", analyze_corrected_code_node)
    graph.add_node("retry_corrected_code", retry_corrected_code_node)
    graph.add_node("finalize", finalize_node)
    graph.set_entry_point("static_analyzer")
    graph.add_edge("static_analyzer", "prepare_detect_prompt")
    graph.add_edge("prepare_detect_prompt", "model_detect_cwes")
    graph.add_conditional_edges("model_detect_cwes", should_continue_detection, {"error": END, "continue": "validate_cwes"})
    graph.add_edge("validate_cwes", "model_generate_corrected_code")
    graph.add_edge("model_generate_corrected_code", "analyze_corrected_code")
    graph.add_conditional_edges("analyze_corrected_code", should_retry_code, {"retry": "retry_corrected_code", "skip": "finalize"})
    graph.add_edge("retry_corrected_code", "analyze_corrected_code")
    graph.add_edge("finalize", END)
    return graph.compile()


def run_analysis(file_name: str, source_code: str) -> dict:
    source_code = deduplicate_repeated_source(normalize_source_newlines(source_code))
    suffix = Path(file_name).suffix or ".c"
    with tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False, encoding="utf-8") as handle:
        handle.write(source_code)
        file_path = handle.name
    try:
        original_code = Path(file_path).read_text(encoding="utf-8", errors="replace")
        language = detect_language(file_path)
        syntax_ok, _syntax_command, syntax_output = syntax_check(Path(file_path), language)
        if not syntax_ok:
            raise SyntaxValidationError("We cannot run the security analysis because you have a syntax error in your code.")

        static_findings = analyze_file(file_path)
        chunks = build_chunks(Path(file_path), file_name, original_code)
        cache_path = cache_chunks(file_name, chunks)
        state: AnalyzerState = {
            "file_path": file_path,
            "file_name": file_name,
            "original_code": original_code,
            "static_findings": static_findings,
            "language": language,
        }

        vulnerabilities: list[dict] = []
        chunk_outputs: list[dict] = []
        seen = set()
        for chunk in chunks:
            model_response = ""
            model_error = ""
            for model_event in iter_analyze_chunk_with_model_events(state, chunk, len(chunks)):
                if model_event.get("event") == "model_delta":
                    model_response += model_event.get("text", "")
                    yield model_event
                elif model_event.get("event") == "_chunk_analysis_complete":
                    model_response = model_event.get("response", model_response)
                    model_error = model_event.get("error", "")
            if model_error:
                if "timeout" in model_error.lower():
                    raise TimeoutError(model_error)
                raise RuntimeError(model_error)
            parsed = extract_json_object(model_response)
            chunk_findings = filter_findings_for_range(static_findings, chunk["start_line"], chunk["end_line"])
            static_vulnerabilities = vulnerabilities_from_static_findings(chunk_findings, state, chunk)
            model_vulnerabilities = normalize_chunk_vulnerabilities(parsed.get("vulnerabilities", []), state, chunk)
            chunk_vulns = merge_unique_vulnerabilities(static_vulnerabilities, model_vulnerabilities)
            summary = f"Reviewed lines {chunk['start_line']}-{chunk['end_line']}"
            unique_chunk_vulns = []
            for vuln in chunk_vulns:
                key = vulnerability_key(vuln)
                if key in seen:
                    continue
                seen.add(key)
                vulnerabilities.append(vuln)
                unique_chunk_vulns.append(vuln)
            chunk_outputs.append(
                {
                    "chunk_index": chunk["index"],
                    "chunk_name": chunk["name"],
                    "chunk_kind": chunk["kind"],
                    "start_line": chunk["start_line"],
                    "end_line": chunk["end_line"],
                    "source_line_count": chunk.get("source_line_count", max(1, len(original_code.splitlines()))),
                    "chunker_version": chunk.get("chunker_version", CHUNKER_VERSION),
                    "code": chunk.get("display_code", chunk.get("content", "")),
                    "summary": summary,
                    "vulnerabilities": unique_chunk_vulns,
                    "corrected_code": "None",
                }
            )

        corrected_chunks: list[str] = []
        for chunk_output, chunk in zip(chunk_outputs, chunks):
            chunk_vulns = chunk_output["vulnerabilities"]
            if chunk_vulns:
                corrected_chunk = ""
                correction_error = ""
                source_chunk = chunk.get("display_code", chunk.get("content", ""))
                for correction_event in iter_corrected_code_events(state, chunk_vulns, source_chunk):
                    if correction_event.get("event") == "correction_delta":
                        yield {
                            **correction_event,
                            "file_path": file_name,
                            "chunk_index": chunk["index"],
                        }
                    elif correction_event.get("event") == "_correction_complete":
                        corrected_chunk = correction_event.get("corrected_code", source_chunk)
                        correction_error = correction_event.get("error", "")
                if correction_error:
                    if "timeout" in correction_error.lower():
                        raise TimeoutError(correction_error)
                    raise RuntimeError(correction_error)
            else:
                corrected_chunk = chunk.get("display_code", chunk.get("content", ""))
            chunk_output["corrected_code"] = corrected_chunk
            corrected_chunks.append(corrected_chunk)

        corrected_code = "\n\n".join(corrected_chunks) if corrected_chunks else "None"
        suffix = ".cpp" if language == "CPP" else ".c"
        with tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False, encoding="utf-8") as handle:
            handle.write(corrected_code)
            candidate = handle.name
        corrected_findings = analyze_file(candidate)
        Path(candidate).unlink(missing_ok=True)
        return {
            "language": "C++" if language == "CPP" else "C",
            "is_vulnerable": bool(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "corrected_code": corrected_code,
            "static_findings": static_findings,
            "corrected_code_is_clean": corrected_findings.strip() == "findings: Code is safe",
            "chunk_outputs": chunk_outputs,
            "chunks_created": len(chunks),
            "chunk_cache_path": str(cache_path),
        }
    finally:
        Path(file_path).unlink(missing_ok=True)


def iter_analysis_events(file_name: str, source_code: str):
    source_code = deduplicate_repeated_source(normalize_source_newlines(source_code))
    suffix = Path(file_name).suffix or ".c"
    with tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False, encoding="utf-8") as handle:
        handle.write(source_code)
        file_path = handle.name
    try:
        yield {"event": "file_started", "file_path": file_name}
        original_code = Path(file_path).read_text(encoding="utf-8", errors="replace")
        language = detect_language(file_path)
        syntax_ok, _syntax_command, _syntax_output = syntax_check(Path(file_path), language)
        if not syntax_ok:
            raise SyntaxValidationError("We cannot run the security analysis because you have a syntax error in your code.")

        yield {"event": "node", "file_path": file_name, "message": "Syntax check passed"}
        static_findings = analyze_file(file_path)
        yield {"event": "node", "file_path": file_name, "message": "Static analyzer evidence collected"}
        chunks = build_chunks(Path(file_path), file_name, original_code)
        cache_path = cache_chunks(file_name, chunks)
        yield {
            "event": "chunks_ready",
            "file_path": file_name,
            "total_chunks": len(chunks),
            "source_lines": max((int(chunk.get("source_line_count", 0)) for chunk in chunks), default=max(1, len(original_code.splitlines()))),
            "chunker_version": chunks[0].get("chunker_version", CHUNKER_VERSION) if chunks else CHUNKER_VERSION,
            "chunks": [
                {
                    "chunk_index": chunk["index"],
                    "chunk_name": chunk["name"],
                    "chunk_kind": chunk["kind"],
                    "start_line": chunk["start_line"],
                    "end_line": chunk["end_line"],
                    "source_line_count": chunk.get("source_line_count", max(1, len(original_code.splitlines()))),
                    "chunker_version": chunk.get("chunker_version", CHUNKER_VERSION),
                    "code": chunk.get("display_code", chunk.get("content", "")),
                    "vulnerabilities": [],
                    "corrected_code": "Pending...",
                    "model_output": "",
                    "analysis_complete": False,
                    "summary": "Waiting for model review.",
                    "file_path": file_name,
                }
                for chunk in chunks
            ],
        }

        state: AnalyzerState = {
            "file_path": file_path,
            "file_name": file_name,
            "original_code": original_code,
            "static_findings": static_findings,
            "language": language,
        }

        vulnerabilities: list[dict] = []
        chunk_outputs: list[dict] = []
        corrected_chunks: list[str] = []
        seen = set()
        for chunk in chunks:
            yield {
                "event": "chunk_started",
                "file_path": file_name,
                "chunk_index": chunk["index"],
                "message": f"Reviewing {file_name}: chunk {chunk['index']} of {len(chunks)}",
            }
            model_response = ""
            model_error = ""
            for model_event in iter_analyze_chunk_with_model_events(state, chunk, len(chunks)):
                if model_event.get("event") == "model_delta":
                    model_response += model_event.get("text", "")
                    yield model_event
                elif model_event.get("event") == "_chunk_analysis_complete":
                    model_response = model_event.get("response", model_response)
                    model_error = model_event.get("error", "")
            if model_error:
                if "timeout" in model_error.lower():
                    raise TimeoutError(model_error)
                raise RuntimeError(model_error)

            parsed = extract_json_object(model_response)
            chunk_findings = filter_findings_for_range(static_findings, chunk["start_line"], chunk["end_line"])
            static_vulnerabilities = vulnerabilities_from_static_findings(chunk_findings, state, chunk)
            model_vulnerabilities = normalize_chunk_vulnerabilities(parsed.get("vulnerabilities", []), state, chunk)
            chunk_vulns = merge_unique_vulnerabilities(static_vulnerabilities, model_vulnerabilities)
            summary = f"Reviewed lines {chunk['start_line']}-{chunk['end_line']}"
            unique_chunk_vulns = []
            for vuln in chunk_vulns:
                key = vulnerability_key(vuln)
                if key in seen:
                    continue
                seen.add(key)
                vulnerabilities.append(vuln)
                unique_chunk_vulns.append(vuln)
            chunk_output = {
                "chunk_index": chunk["index"],
                "chunk_name": chunk["name"],
                "chunk_kind": chunk["kind"],
                "start_line": chunk["start_line"],
                "end_line": chunk["end_line"],
                "source_line_count": chunk.get("source_line_count", max(1, len(original_code.splitlines()))),
                "chunker_version": chunk.get("chunker_version", CHUNKER_VERSION),
                "code": chunk.get("display_code", chunk.get("content", "")),
                "summary": summary,
                "vulnerabilities": unique_chunk_vulns,
                "corrected_code": "Pending...",
                "model_output": model_response,
                "analysis_complete": True,
                "file_path": file_name,
            }
            chunk_outputs.append(chunk_output)
            yield {"event": "chunk_result", "file_path": file_name, "chunk": chunk_output}
            yield {
                "event": "correction_started",
                "file_path": file_name,
                "chunk_index": chunk["index"],
                "message": f"Generating corrected code for chunk {chunk['index']}",
            }
            chunk_vulns = chunk_output["vulnerabilities"]
            if chunk_vulns:
                corrected_chunk = ""
                correction_error = ""
                source_chunk = chunk.get("display_code", chunk.get("content", ""))
                for correction_event in iter_corrected_code_events(state, chunk_vulns, source_chunk):
                    if correction_event.get("event") == "correction_delta":
                        yield {
                            **correction_event,
                            "file_path": file_name,
                            "chunk_index": chunk["index"],
                        }
                    elif correction_event.get("event") == "_correction_complete":
                        corrected_chunk = correction_event.get("corrected_code", source_chunk)
                        correction_error = correction_event.get("error", "")
                if correction_error:
                    if "timeout" in correction_error.lower():
                        raise TimeoutError(correction_error)
                    raise RuntimeError(correction_error)
            else:
                corrected_chunk = chunk.get("display_code", chunk.get("content", ""))
            chunk_output["corrected_code"] = corrected_chunk
            corrected_chunks.append(corrected_chunk)
            yield {
                "event": "correction_result",
                "file_path": file_name,
                "chunk_index": chunk["index"],
                "corrected_code": corrected_chunk,
            }

        corrected_code = "\n\n".join(corrected_chunks) if corrected_chunks else "None"
        candidate_suffix = ".cpp" if language == "CPP" else ".c"
        with tempfile.NamedTemporaryFile("w", suffix=candidate_suffix, delete=False, encoding="utf-8") as handle:
            handle.write(corrected_code)
            candidate = handle.name
        corrected_findings = analyze_file(candidate)
        Path(candidate).unlink(missing_ok=True)
        result = {
            "language": "C++" if language == "CPP" else "C",
            "is_vulnerable": bool(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "corrected_code": corrected_code,
            "static_findings": static_findings,
            "corrected_code_is_clean": corrected_findings.strip() == "findings: Code is safe",
            "chunk_outputs": chunk_outputs,
            "chunks_created": len(chunks),
            "chunk_cache_path": str(cache_path),
        }
        yield {"event": "file_result", "file_path": file_name, "result": result}
    finally:
        Path(file_path).unlink(missing_ok=True)
