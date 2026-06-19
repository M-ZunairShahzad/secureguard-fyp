import io
import json
import os
import re
import time
import zipfile
from fastapi import APIRouter, Body, Depends, File, Form, HTTPException, Query, Response, UploadFile, status
from fastapi.responses import StreamingResponse
from supabase import Client

from app.dependencies import get_supabase, get_current_user
from app.models.scans import BranchFilesResponse, ScanRequest, ScanResponse, UploadScanRequest
from app.services.scans import scanner_service
from app.services.scans.scan_storage_service import (
    create_scan_record,
    create_failed_scan_record,
    save_vulnerabilities,
)
from app.services.scans.personal_scan_persistence_service import (
    build_scan_pdf_for_user,
    create_scan_started,
    create_on_demand_report,
    delete_on_demand_report,
    delete_scan_for_user_new,
    download_corrected_code_zip,
    download_on_demand_report,
    get_scan_detail_new,
    get_scans_for_user_new,
    list_on_demand_reports,
    mark_scan_failed,
    save_scan_success,
)
from app.services.project_files.file_service import save_scanned_sources_zip
from app.services.teams.team_service import link_project_to_team

router = APIRouter()

C_CPP_EXTENSIONS = {".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hxx"}
NO_SOURCE_FILES_MESSAGE = (
    "This ZIP does not contain any C or C++ source files. "
    "Please upload a ZIP with .c, .cpp, .h, .hpp, .cc, .cxx, or .hxx files."
)


def _normalize_source_newlines(source_code: str) -> str:
    return re.sub(r"\r+\n", "\n", source_code).replace("\r", "\n")


def _suspicious_filename_message(filename: str, *, in_zip: bool = False) -> str:
    location = " inside the ZIP" if in_zip else ""
    upload_target = " and upload the ZIP again" if in_zip else " and upload it again"
    return f"Suspicious file name found{location}: {filename}. Rename the file{upload_target}."


def _normalize_safe_upload_path(filename: str) -> str:
    normalized = (filename or "").replace("\\", "/").strip().lstrip("/")
    parts = normalized.split("/")
    if (
        not normalized
        or normalized.startswith("../")
        or "/../" in normalized
        or normalized.endswith("/..")
        or normalized.startswith("./")
        or "/./" in normalized
        or normalized.endswith("/.")
        or any(part == "" for part in parts)
        or (len(normalized) > 1 and normalized[1] == ":")
        or any(ord(char) < 32 for char in normalized)
    ):
        raise ValueError(filename)
    return normalized


async def _extract_upload_files(files: list[UploadFile]) -> dict[str, str]:
    extracted: dict[str, str] = {}
    rejected: list[str] = []

    for upload in files:
        raw_filename = (upload.filename or "").strip()
        try:
            filename = _normalize_safe_upload_path(raw_filename)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=_suspicious_filename_message(raw_filename or "unnamed file"),
            )
        content = await upload.read()
        ext = os.path.splitext(filename)[1].lower()

        if ext == ".zip":
            try:
                with zipfile.ZipFile(io.BytesIO(content)) as archive:
                    for entry in archive.infolist():
                        if entry.is_dir():
                            continue
                        try:
                            inner_name = _normalize_safe_upload_path(entry.filename)
                        except ValueError:
                            raise HTTPException(
                                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                                detail=_suspicious_filename_message(entry.filename, in_zip=True),
                            )
                        inner_ext = os.path.splitext(inner_name)[1].lower()
                        if inner_ext not in C_CPP_EXTENSIONS:
                            rejected.append(inner_name)
                            continue
                        key = inner_name
                        duplicate_index = 2
                        while key in extracted:
                            stem, suffix = os.path.splitext(inner_name)
                            key = f"{stem}-{duplicate_index}{suffix}"
                            duplicate_index += 1
                        extracted[key] = _normalize_source_newlines(
                            archive.read(entry).decode("utf-8", errors="replace")
                        )
            except zipfile.BadZipFile:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"Invalid ZIP archive: {filename}",
                )
            continue

        if ext not in C_CPP_EXTENSIONS:
            rejected.append(filename)
            continue
        extracted[filename] = _normalize_source_newlines(content.decode("utf-8", errors="replace"))

    if not extracted:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=NO_SOURCE_FILES_MESSAGE,
        )

    return extracted

@router.get("/{team_id}/github/files", response_model=BranchFilesResponse)
async def get_branch_files(
    team_id: str,
    branch: str,
    current_user=Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    """
    Returns a list of all C/C++ file paths for a given branch in the connected GitHub repository.
    """
    files = await scanner_service.fetch_branch_files(team_id, branch, current_user.id, supabase)
    return BranchFilesResponse(files=files)

@router.post("/{team_id}/scans", response_model=ScanResponse)
async def start_scan(
    team_id: str,
    body: ScanRequest,
    current_user=Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    """
    Fetches files from GitHub and scans them, saving results to Supabase.
    """
    start_time = time.time()
    scan_id = None
    link_project_to_team(team_id, body.project_id, current_user.id, supabase)
    files_dict = await scanner_service.fetch_selected_code_hybrid(
        team_id,
        body.branch,
        body.selected_files,
        current_user.id,
        supabase
    )
    save_scanned_sources_zip(body.project_id, current_user.id, files_dict, supabase)
    scan_id = create_scan_started(
        supabase,
        current_user.id,
        body.project_id,
        files_dict,
        "github",
    )
    try:
        result = await scanner_service.run_vulnerability_scanner(files_dict)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY:
            raise
        duration = int(time.time() - start_time)
        if scan_id:
            mark_scan_failed(supabase, scan_id, str(exc.detail))
        raise
    except Exception as exc:
        duration = int(time.time() - start_time)
        if scan_id:
            mark_scan_failed(supabase, scan_id, str(exc))
        raise
    duration = int(time.time() - start_time)

    try:
        persisted = save_scan_success(
            supabase,
            current_user.id,
            body.project_id,
            scan_id,
            files_dict,
            result,
            duration,
        )
        result["scan_id"] = scan_id
        result["scan_persistence"] = persisted
    except Exception as e:
        print(f"[scans] Failed to save scan to DB: {e}")
        if scan_id:
            mark_scan_failed(supabase, scan_id, str(e))
        raise

    return ScanResponse(**result)


@router.post("/{team_id}/scans/stream")
async def stream_team_scan(
    team_id: str,
    body: ScanRequest,
    current_user=Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    started_at = time.time()
    link_project_to_team(team_id, body.project_id, current_user.id, supabase)
    files_dict = await scanner_service.fetch_selected_code_hybrid(
        team_id, body.branch, body.selected_files, current_user.id, supabase
    )
    save_scanned_sources_zip(body.project_id, current_user.id, files_dict, supabase)
    scan_id = create_scan_started(supabase, current_user.id, body.project_id, files_dict, "github")

    def events():
        for event in scanner_service.iter_vulnerability_scanner_events(files_dict):
            if event.get("event") == "scan_started":
                event = {**event, "scan_id": scan_id}
            if event.get("event") == "error":
                mark_scan_failed(supabase, scan_id, event.get("message", "Scan failed"))
                yield json.dumps(event, ensure_ascii=False) + "\n"
                return
            if event.get("event") == "scan_result":
                result = event["result"]
                persisted = save_scan_success(
                    supabase, current_user.id, body.project_id, scan_id, files_dict,
                    result, int(time.time() - started_at),
                )
                result["scan_id"] = scan_id
                result["scan_persistence"] = persisted
                event = {"event": "scan_result", "result": result}
            yield json.dumps(event, ensure_ascii=False) + "\n"

    return StreamingResponse(events(), media_type="application/x-ndjson", headers={"X-Accel-Buffering": "no"})

@router.post("/scan/upload", response_model=ScanResponse)
async def scan_uploaded_file(
    body: UploadScanRequest,
    current_user=Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    """
    Scans a single uploaded file and saves results to Supabase.
    """
    start_time = time.time()
    try:
        filename = _normalize_safe_upload_path(body.filename)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=_suspicious_filename_message(body.filename or "unnamed file"),
        )
    files_dict = {filename: body.source_code}
    save_scanned_sources_zip(body.project_id, current_user.id, files_dict, supabase)
    try:
        result = await scanner_service.run_vulnerability_scanner(files_dict)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY:
            raise
        duration = int(time.time() - start_time)
        create_failed_scan_record(
            supabase,
            current_user.id,
            body.project_id,
            {"project_name": body.project_name, "scan_type": "upload", "file_name": filename, "duration_secs": duration},
            str(exc.detail),
        )
        raise
    except Exception as exc:
        duration = int(time.time() - start_time)
        create_failed_scan_record(
            supabase,
            current_user.id,
            body.project_id,
            {"project_name": body.project_name, "scan_type": "upload", "file_name": filename, "duration_secs": duration},
            str(exc),
        )
        raise
    duration = int(time.time() - start_time)

    # Save to database
    try:
        scan_data = {
            **result,
            "project_name": body.project_name,
            "scan_type": "upload",
            "file_name": filename,
            "duration_secs": duration,
        }
        scan_id = create_scan_record(supabase, current_user.id, body.project_id, scan_data)
        save_vulnerabilities(supabase, scan_id, result["vulnerabilities"])
        result["scan_id"] = scan_id
    except Exception as e:
        print(f"[scans] Failed to save scan to DB: {e}")
        result["scan_id"] = None

    return ScanResponse(**result)


@router.post("/scan/upload-files", response_model=ScanResponse)
async def scan_uploaded_files(
    files: list[UploadFile] = File(...),
    project_id: str = Form(""),
    project_name: str = Form(""),
    current_user=Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    """
    Scans uploaded C/C++ files or ZIP archives.
    ZIP archives are unpacked in memory; only C/C++ files are scanned.
    """
    start_time = time.time()
    files_dict = await _extract_upload_files(files)
    save_scanned_sources_zip(project_id, current_user.id, files_dict, supabase)
    try:
        result = await scanner_service.run_vulnerability_scanner(files_dict)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY:
            raise
        duration = int(time.time() - start_time)
        create_failed_scan_record(
            supabase,
            current_user.id,
            project_id,
            {"project_name": project_name, "scan_type": "upload", "file_name": ", ".join(files_dict.keys())[:500], "duration_secs": duration},
            str(exc.detail),
        )
        raise
    except Exception as exc:
        duration = int(time.time() - start_time)
        create_failed_scan_record(
            supabase,
            current_user.id,
            project_id,
            {"project_name": project_name, "scan_type": "upload", "file_name": ", ".join(files_dict.keys())[:500], "duration_secs": duration},
            str(exc),
        )
        raise
    duration = int(time.time() - start_time)

    try:
        scan_data = {
            **result,
            "project_name": project_name,
            "scan_type": "upload",
            "file_name": ", ".join(files_dict.keys())[:500],
            "duration_secs": duration,
        }
        scan_id = create_scan_record(supabase, current_user.id, project_id, scan_data)
        save_vulnerabilities(supabase, scan_id, result["vulnerabilities"])
        result["scan_id"] = scan_id
    except Exception as e:
        print(f"[scans] Failed to save scan to DB: {e}")
        result["scan_id"] = None

    return ScanResponse(**result)


@router.post("/scan/upload-files/stream")
async def scan_uploaded_files_stream(
    files: list[UploadFile] = File(...),
    project_id: str = Form(""),
    project_name: str = Form(""),
    current_user=Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    """
    Streams uploaded C/C++ scan progress as newline-delimited JSON.
    Each line is one event object; the final scan_result event includes the persisted scan_id.
    """
    start_time = time.time()
    files_dict = await _extract_upload_files(files)
    save_scanned_sources_zip(project_id, current_user.id, files_dict, supabase)
    scan_id = create_scan_started(supabase, current_user.id, project_id, files_dict, "upload")

    def line(event: dict) -> str:
        return json.dumps(event, ensure_ascii=False) + "\n"

    def event_stream():
        final_result = None
        terminal_status_saved = False
        try:
            for event in scanner_service.iter_vulnerability_scanner_events(files_dict):
                if event.get("event") == "scan_started":
                    event = {**event, "scan_id": scan_id}
                if event.get("event") == "error":
                    mark_scan_failed(supabase, scan_id, event.get("message", "Scan failed"))
                    terminal_status_saved = True
                    yield line(event)
                    return
                if event.get("event") == "scan_result":
                    final_result = event["result"]
                    duration = int(time.time() - start_time)
                    try:
                        current_scan = (
                            supabase.table("scan")
                            .select("completion_status,error_message")
                            .eq("scan_id", scan_id)
                            .limit(1)
                            .execute()
                        )
                        current_scan_row = (current_scan.data or [{}])[0]
                        if (
                            current_scan_row.get("completion_status") == "failed"
                            and "cancelled by user" in str(current_scan_row.get("error_message") or "").lower()
                        ):
                            terminal_status_saved = True
                            return
                        persisted = save_scan_success(
                            supabase,
                            current_user.id,
                            project_id,
                            scan_id,
                            files_dict,
                            final_result,
                            duration,
                        )
                        final_result["scan_id"] = scan_id
                        final_result["scan_persistence"] = persisted
                        terminal_status_saved = True
                    except Exception as exc:
                        print(f"[scans] Failed to save streamed scan to DB: {exc}")
                        mark_scan_failed(supabase, scan_id, str(exc))
                        terminal_status_saved = True
                        final_result["scan_id"] = None
                    yield line({"event": "scan_result", "result": final_result})
                    return
                yield line(event)

            if final_result is None:
                mark_scan_failed(supabase, scan_id, "Scan ended before a report was produced.")
                terminal_status_saved = True
                yield line({"event": "error", "message": "Scan ended before a report was produced."})
        finally:
            if not terminal_status_saved:
                mark_scan_failed(supabase, scan_id, "Scan cancelled by user.")

    return StreamingResponse(
        event_stream(),
        media_type="application/x-ndjson",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )

@router.get("/scans/history", response_model=list[dict])
async def get_scan_history(
    current_user=Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    """
    Returns all past scans for the current authenticated user.
    """
    scans = get_scans_for_user_new(supabase, current_user.id)
    return scans


@router.delete("/scans/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan_history(
    scan_id: str,
    current_user=Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    """Delete one scan history row and its linked reports for the current user."""
    try:
        delete_scan_for_user_new(supabase, scan_id, current_user.id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/scans/{scan_id}/cancel", status_code=status.HTTP_204_NO_CONTENT)
async def cancel_scan(
    scan_id: str,
    current_user=Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    scan_result = (
        supabase.table("scan")
        .select("scan_id")
        .eq("scan_id", scan_id)
        .eq("user_id", current_user.id)
        .limit(1)
        .execute()
    )
    if not scan_result.data:
        raise HTTPException(status_code=404, detail="Scan not found.")
    mark_scan_failed(supabase, scan_id, "Scan cancelled by user.")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/reports", response_model=list[dict])
async def get_reports(
    current_user=Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    """Returns generated report metadata for the authenticated user."""
    return list_on_demand_reports(supabase, current_user.id)


@router.post("/reports", response_model=list[dict])
async def generate_report(
    body: dict = Body(...),
    current_user=Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    """Generate PDF, CSV, or both from the latest completed scan for a project."""
    report_type = body.get("report_type", "full")
    if report_type != "full":
        raise HTTPException(status_code=422, detail="Team reports are not available yet.")

    project_id = str(body.get("project_id") or "").strip()
    if not project_id:
        raise HTTPException(status_code=422, detail="Select a project before generating a report.")

    report_format = str(body.get("format") or "pdf").lower()
    if report_format not in {"pdf", "csv", "both"}:
        raise HTTPException(status_code=422, detail="Report format must be pdf, csv, or both.")

    try:
        return create_on_demand_report(
            supabase,
            current_user.id,
            project_id,
            report_format,
            body.get("start_date"),
            body.get("end_date"),
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/reports/{report_id}/download")
async def download_report(
    report_id: str,
    format: str | None = Query(default=None, pattern="^(pdf|csv)$"),
    current_user=Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    """Download an on-demand stored PDF/CSV report."""
    try:
        content, filename, media_type = download_on_demand_report(supabase, report_id, current_user.id, format)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/reports/{report_id}/download-code")
async def download_report_code(
    report_id: str,
    current_user=Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    """Download original scanned code and corrected code as a ZIP."""
    try:
        content, filename = download_corrected_code_zip(supabase, report_id, current_user.id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    return Response(
        content=content,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.delete("/reports/{report_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_report(
    report_id: str,
    current_user=Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    """Delete one generated report artifact for the current user."""
    try:
        delete_on_demand_report(supabase, report_id, current_user.id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/scans/{scan_id}", response_model=dict)
async def get_scan_detail(
    scan_id: str,
    current_user=Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    """
    Returns a single scan with its full vulnerability list.
    """
    try:
        scan = get_scan_detail_new(supabase, scan_id, current_user.id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return scan


@router.get("/scans/{scan_id}/report-pdf")
async def get_scan_report_pdf(
    scan_id: str,
    current_user=Depends(get_current_user),
    supabase: Client = Depends(get_supabase),
):
    try:
        pdf_bytes = build_scan_pdf_for_user(supabase, scan_id, current_user.id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'inline; filename="secureguard-report-{scan_id}.pdf"'},
    )
