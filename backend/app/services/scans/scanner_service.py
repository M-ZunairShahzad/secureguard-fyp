import httpx
import asyncio
import io
import traceback
import zipfile
import base64
from fastapi import HTTPException, status
from supabase import Client
from typing import List, Dict

from app.services.teams.github_service import _get_installation_token, _parse_github_owner_repo
from app.services.teams.team_service import require_member
from app.services.model_scanner.graph_runner import SyntaxValidationError, iter_analysis_events, run_analysis

GITHUB_API = "https://api.github.com"
C_CPP_EXTENSIONS = ('.c', '.cpp', '.h', '.hpp', '.cc', '.cxx', '.hxx')


def _run_analysis_to_result(file_path: str, source_code: str) -> dict:
    """Consume the event-producing analysis generator and return its result.

    The project/team GitHub scan endpoints are non-streaming. ``run_analysis``
    became an event generator when model/correction deltas were added, so these
    callers must consume it instead of indexing the generator itself.
    """
    analysis = run_analysis(file_path, source_code)
    if isinstance(analysis, dict):
        return analysis
    while True:
        try:
            next(analysis)
        except StopIteration as completed:
            result = completed.value
            if not isinstance(result, dict):
                raise RuntimeError("Model scan ended before returning a result.")
            return result


def _safe_chunk_count(result: dict, source_code: str) -> int:
    chunks_created = result.get("chunks_created")
    if isinstance(chunks_created, int) and chunks_created > 0:
        return chunks_created
    chunk_outputs = result.get("chunk_outputs") or []
    if chunk_outputs:
        return len(chunk_outputs)
    return max(1, source_code.count("\n") + 1)


def _corrected_code_from_chunks(chunk_outputs: list[dict]) -> str:
    corrected_chunks = []
    for chunk in sorted(chunk_outputs, key=lambda item: int(item.get("chunk_index") or 0)):
        corrected = chunk.get("corrected_code")
        if corrected and corrected not in {"None", "Pending..."}:
            corrected_chunks.append(corrected)
    return "\n\n".join(corrected_chunks) if corrected_chunks else "None"

async def _get_token_for_team(team_id: str, supabase: Client) -> str:
    """Helper to get a fresh installation token for a team."""
    team_result = (
        supabase.table("team")
        .select("github_installation_id")
        .eq("team_id", team_id)
        .single()
        .execute()
    )
    installation_id = team_result.data.get("github_installation_id") if team_result.data else None

    if not installation_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="GitHub App is not installed for this team. Connect GitHub first.",
        )
    return await _get_installation_token(installation_id)

async def fetch_branch_files(team_id: str, branch_name: str, user_id: str, supabase: Client) -> List[str]:
    """
    Fetches the Git tree for a branch and filters it to return only C/C++ files.
    """
    require_member(team_id, user_id, supabase)
    
    team_result = (
        supabase.table("team")
        .select("github_repo")
        .eq("team_id", team_id)
        .single()
        .execute()
    )
    repo_url = team_result.data.get("github_repo")
    if not repo_url:
        raise HTTPException(status_code=400, detail="Team has no connected GitHub repository.")

    owner, repo = _parse_github_owner_repo(repo_url)
    token = await _get_token_for_team(team_id, supabase)

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    async with httpx.AsyncClient(timeout=15.0) as client:
        # Get the tree for the branch
        resp = await client.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/git/trees/{branch_name}?recursive=1",
            headers=headers
        )
        
        if resp.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Failed to fetch branch tree: {resp.status_code}"
            )
            
        tree_data = resp.json()
        if "tree" not in tree_data:
            return []

        # Filter for C/C++ files
        c_cpp_files = [
            item["path"] for item in tree_data["tree"]
            if item["type"] == "blob" and item["path"].lower().endswith(C_CPP_EXTENSIONS)
        ]
        
        return c_cpp_files

async def _fetch_blob_content(
    client: httpx.AsyncClient,
    owner: str,
    repo: str,
    file_path: str,
    branch: str,
    headers: dict,
) -> tuple[str, str]:
    """Fetches a single file's content via the GitHub Contents API."""
    resp = await client.get(
        f"{GITHUB_API}/repos/{owner}/{repo}/contents/{file_path}",
        headers=headers,
        params={"ref": branch},
    )
    if resp.status_code == 200:
        data = resp.json()
        if data.get("encoding") == "base64" and "content" in data:
            content = base64.b64decode(data["content"]).decode("utf-8", errors="replace")
            return file_path, content
    return file_path, ""

async def fetch_selected_code_hybrid(team_id: str, branch_name: str, selected_files: List[str], user_id: str, supabase: Client) -> Dict[str, str]:
    """
    Smartly fetches the content of the selected files.
    If < 50 files, uses concurrent API requests (Blob API).
    If >= 50 files, downloads the zipball and extracts only what's needed in memory.
    """
    require_member(team_id, user_id, supabase)

    if not selected_files:
        return {}

    team_result = (
        supabase.table("team")
        .select("github_repo")
        .eq("team_id", team_id)
        .single()
        .execute()
    )
    repo_url = team_result.data.get("github_repo")
    if not repo_url:
        raise HTTPException(status_code=400, detail="Team has no connected GitHub repository.")

    owner, repo = _parse_github_owner_repo(repo_url)
    token = await _get_token_for_team(team_id, supabase)

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    files_content: Dict[str, str] = {}

    if len(selected_files) < 50:
        # ---------------------------------------------------------
        # BLOB APPROACH: Concurrent HTTP requests for small batches
        # ---------------------------------------------------------
        async with httpx.AsyncClient(timeout=30.0) as client:
            tasks = [
                _fetch_blob_content(client, owner, repo, path, branch_name, headers)
                for path in selected_files
            ]
            results = await asyncio.gather(*tasks)
            for file_path, content in results:
                if content:
                    files_content[file_path] = content
    else:
        # ---------------------------------------------------------
        # ZIPBALL APPROACH: Download zip into memory, extract targeted files
        # ---------------------------------------------------------
        async with httpx.AsyncClient(timeout=60.0, follow_redirects=True) as client:
            resp = await client.get(
                f"{GITHUB_API}/repos/{owner}/{repo}/zipball/{branch_name}",
                headers=headers
            )
            if resp.status_code != 200:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"Failed to download repository zip: {resp.status_code}"
                )
            
            # Read ZIP into memory buffer
            zip_buffer = io.BytesIO(resp.content)
            
            with zipfile.ZipFile(zip_buffer, "r") as zip_ref:
                # GitHub zips put everything inside a root directory with a dynamic name (owner-repo-sha)
                # We need to strip that first directory component to match our selected_files paths.
                for zip_info in zip_ref.infolist():
                    if zip_info.is_dir():
                        continue
                    
                    # Split path and remove the root folder
                    parts = zip_info.filename.split("/", 1)
                    if len(parts) < 2:
                        continue
                    
                    actual_path = parts[1]
                    if actual_path in selected_files:
                        with zip_ref.open(zip_info) as f:
                            files_content[actual_path] = f.read().decode("utf-8", errors="replace")

    return files_content

async def run_vulnerability_scanner(files_dict: Dict[str, str]) -> dict:
    """
    Runs the trained model scanner for every C/C++ file and aggregates results.
    """
    all_vulnerabilities = []
    files_scanned = []
    total_chunks = 0

    for file_path, source_code in files_dict.items():
        if not source_code.strip():
            continue

        try:
            result = _run_analysis_to_result(file_path, source_code)

            # Tag each vulnerability with which file it came from
            for vuln in result["vulnerabilities"]:
                vuln["file_path"] = file_path

            all_vulnerabilities.extend(result["vulnerabilities"])
            chunks_scanned = _safe_chunk_count(result, source_code)
            total_chunks += chunks_scanned
            files_scanned.append({
                "file_path": file_path,
                "chunks_scanned": chunks_scanned,
                "vulnerabilities_found": len(result["vulnerabilities"]),
                "risk_level": "Vulnerable" if result["vulnerabilities"] else "Safe",
                "language": result.get("language", ""),
                "static_findings": result.get("static_findings", ""),
                "corrected_code": result.get("corrected_code", "None"),
                "corrected_code_is_clean": result.get("corrected_code_is_clean", False),
                "chunk_outputs": result.get("chunk_outputs", []),
            })

        except SyntaxValidationError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=str(exc),
            ) from exc
        except TimeoutError as exc:
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail=f"Model scan failed for {file_path}: Request timeout exceeded. Please try again.",
            ) from exc
        except Exception as exc:
            print(f"[scanner_service] Failed to scan {file_path}: {exc}")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Model scan failed for {file_path}. Please try again.",
            ) from exc

    # Calculate overall risk score across all files
    severity_points = {"Critical": 10, "High": 7, "Medium": 4, "Low": 1}
    total_score = sum(
        severity_points.get(v.get("severity", ""), 0)
        for v in all_vulnerabilities
    )

    if total_score == 0:
        overall_risk = "Safe"
    elif total_score < 10:
        overall_risk = "Low Risk"
    elif total_score < 30:
        overall_risk = "Medium Risk"
    elif total_score < 60:
        overall_risk = "High Risk"
    else:
        overall_risk = "Critical Risk"

    return {
        "status": "success",
        "total_vulnerabilities": len(all_vulnerabilities),
        "overall_risk_level": overall_risk,
        "overall_risk_score": total_score,
        "files_analyzed": len(files_scanned),
        "total_chunks_scanned": total_chunks,
        "files_summary": [
            {
                "file_path": item["file_path"],
                "chunks_scanned": item["chunks_scanned"],
                "vulnerabilities_found": item["vulnerabilities_found"],
                "risk_level": item["risk_level"],
            }
            for item in files_scanned
        ],
        "vulnerabilities": all_vulnerabilities,
        "corrected_code": "None",
        "files": [
            {
                "filename": item["file_path"],
                "language": item.get("language", ""),
                "corrected_code": item.get("corrected_code", "None"),
                "static_findings": item.get("static_findings", ""),
                "corrected_code_is_clean": item.get("corrected_code_is_clean", False),
                "chunk_outputs": item.get("chunk_outputs", []),
            }
            for item in files_scanned
        ],
        "chunk_outputs": [
            {**chunk, "file_path": item["file_path"]}
            for item in files_scanned
            for chunk in item.get("chunk_outputs", [])
        ],
    }


def build_scan_response_from_file_results(file_results: list[tuple[str, dict]]) -> dict:
    all_vulnerabilities = []
    files_scanned = []
    total_chunks = 0

    for file_path, result in file_results:
        for vuln in result["vulnerabilities"]:
            vuln["file_path"] = file_path
        all_vulnerabilities.extend(result["vulnerabilities"])
        chunk_outputs = result.get("chunk_outputs", [])
        chunks_scanned = len(chunk_outputs) or int(result.get("chunks_created") or 0)
        total_chunks += chunks_scanned
        files_scanned.append({
            "file_path": file_path,
            "chunks_scanned": chunks_scanned,
            "vulnerabilities_found": len(result["vulnerabilities"]),
            "risk_level": "Vulnerable" if result["vulnerabilities"] else "Safe",
            "language": result.get("language", ""),
            "static_findings": result.get("static_findings", ""),
            "corrected_code": result.get("corrected_code") or _corrected_code_from_chunks(chunk_outputs),
            "corrected_code_is_clean": result.get("corrected_code_is_clean", False),
            "chunk_outputs": chunk_outputs,
        })

    severity_points = {"Critical": 10, "High": 7, "Medium": 4, "Low": 1}
    total_score = sum(severity_points.get(v.get("severity", ""), 0) for v in all_vulnerabilities)
    if total_score == 0:
        overall_risk = "Safe"
    elif total_score < 10:
        overall_risk = "Low Risk"
    elif total_score < 30:
        overall_risk = "Medium Risk"
    elif total_score < 60:
        overall_risk = "High Risk"
    else:
        overall_risk = "Critical Risk"

    return {
        "status": "success",
        "total_vulnerabilities": len(all_vulnerabilities),
        "overall_risk_level": overall_risk,
        "overall_risk_score": total_score,
        "files_analyzed": len(files_scanned),
        "total_chunks_scanned": total_chunks,
        "files_summary": [
            {
                "file_path": item["file_path"],
                "chunks_scanned": item["chunks_scanned"],
                "vulnerabilities_found": item["vulnerabilities_found"],
                "risk_level": item["risk_level"],
            }
            for item in files_scanned
        ],
        "vulnerabilities": all_vulnerabilities,
        "corrected_code": files_scanned[0].get("corrected_code", "None") if len(files_scanned) == 1 else "None",
        "files": [
            {
                "filename": item["file_path"],
                "language": item.get("language", ""),
                "corrected_code": item.get("corrected_code", "None"),
                "static_findings": item.get("static_findings", ""),
                "corrected_code_is_clean": item.get("corrected_code_is_clean", False),
                "chunk_outputs": item.get("chunk_outputs", []),
            }
            for item in files_scanned
        ],
        "chunk_outputs": [
            {**chunk, "file_path": item["file_path"]}
            for item in files_scanned
            for chunk in item.get("chunk_outputs", [])
        ],
    }


def iter_vulnerability_scanner_events(files_dict: Dict[str, str]):
    file_results: list[tuple[str, dict]] = []
    total_files = sum(1 for source_code in files_dict.values() if source_code.strip())
    yield {"event": "scan_started", "total_files": total_files}

    for file_path, source_code in files_dict.items():
        if not source_code.strip():
            continue
        try:
            file_result = None
            for event in iter_analysis_events(file_path, source_code):
                if event.get("event") == "file_result":
                    file_result = event["result"]
                yield event
            if file_result is None:
                raise RuntimeError("Model scan did not return a file result.")
            file_results.append((file_path, file_result))
        except SyntaxValidationError as exc:
            yield {"event": "error", "status_code": status.HTTP_422_UNPROCESSABLE_ENTITY, "message": str(exc)}
            return
        except TimeoutError:
            yield {
                "event": "error",
                "status_code": status.HTTP_504_GATEWAY_TIMEOUT,
                "message": f"Model scan failed for {file_path}: Request timeout exceeded. Please try again.",
            }
            return
        except Exception as exc:
            # Do not discard the underlying scanner/provider failure. The
            # generic message made local and production failures impossible to
            # distinguish (invalid model JSON, provider error, parser error,
            # etc.) and left the UI with no actionable information.
            print(f"[scanner_service] Failed to scan {file_path}: {type(exc).__name__}: {exc}")
            traceback.print_exc()
            detail = str(exc).strip()
            yield {
                "event": "error",
                "status_code": status.HTTP_502_BAD_GATEWAY,
                "message": (
                    f"Model scan failed for {file_path}: {detail}"
                    if detail
                    else f"Model scan failed for {file_path}. Please try again."
                ),
            }
            return

    yield {"event": "scan_result", "result": build_scan_response_from_file_results(file_results)}
