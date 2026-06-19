import { apiFetch } from "@/lib/teams-api";

// ---------------------------------------------------------------------------
// Types — mirror the backend Pydantic response schemas exactly
// ---------------------------------------------------------------------------

export interface VulnerabilityDetail {
  cwe_id: string;
  cwe_name: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  line_number: number;
  absolute_line: number;
  location: string;
  description: string;
  fix_suggestion: string;
  affected_code: string;
  function_name: string;
  file_path: string;
}

export interface FileSummary {
  file_path: string;
  chunks_scanned: number;
  vulnerabilities_found: number;
  risk_level: string;
}

export interface ScanResult {
  status: string;
  total_vulnerabilities: number;
  overall_risk_level: string;
  overall_risk_score: number;
  files_analyzed: number;
  total_chunks_scanned: number;
  files_summary: FileSummary[];
  vulnerabilities: VulnerabilityDetail[];
  corrected_code: string;
  files: Array<{
    filename: string;
    language: string;
    corrected_code: string;
    static_findings: string;
    corrected_code_is_clean: boolean;
    chunk_outputs?: ChunkOutput[];
  }>;
  chunk_outputs?: ChunkOutput[];
  scan_id?: string | null;
}

export interface ChunkOutput {
  file_path?: string;
  chunk_index: number;
  chunk_name: string;
  chunk_kind: string;
  start_line: number;
  end_line: number;
  source_line_count?: number;
  chunker_version?: string;
  code?: string;
  summary?: string;
  vulnerabilities: VulnerabilityDetail[];
  corrected_code?: string;
  model_output?: string;
  analysis_complete?: boolean;
}

export interface BranchFilesResponse {
  files: string[];
}

export interface ScanHistoryItem {
  id: string;
  project_id: string | null;
  project_name: string | null;
  scan_type: string | null;
  file_name: string | null;
  branch: string | null;
  status: string;
  risk_level: string | null;
  risk_score: number | null;
  total_vulns: number | null;
  files_scanned: number | null;
  duration_secs: number | null;
  error_message: string | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  report_storage_path?: string | null;
  report_expires_at?: string | null;
  corrected_code?: string | null;
  chunk_outputs?: ChunkOutput[] | null;
  severity_counts?: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  critical_findings?: Array<{
    id: string;
    severity: string;
    cwe_id: string | null;
    cwe_name: string | null;
    type: string | null;
    line_number: number | null;
    file_path: string | null;
    description: string;
    created_at: string;
  }>;
  alert_findings?: Array<{
    id: string;
    scan_id: string;
    severity: string;
    cwe_id: string | null;
    cwe_name: string | null;
    type: string | null;
    line_number: number | null;
    file_path: string | null;
    description: string;
    created_at: string;
  }>;
}

export interface StoredVulnerability {
  id: string;
  scan_id: string;
  severity: string;
  type: string;
  cwe_id: string | null;
  cwe_name: string | null;
  line_number: number | null;
  absolute_line: number | null;
  description: string;
  fix_suggestion: string | null;
  function_name: string | null;
  file_path: string | null;
  code_snippet: string | null;
  location?: string | null;
  created_at: string;
}

export interface ScanDetailResult {
  scan: ScanHistoryItem;
  vulnerabilities: StoredVulnerability[];
  source_files?: Array<{
    filename: string;
    source_code: string;
    storage_path?: string | null;
  }>;
}

export interface ReportItem {
  id: string;
  scan_id: string | null;
  user_id: string;
  name: string;
  type?: "personal" | "team";
  format: "pdf" | "csv";
  status: "pending" | "completed" | "failed";
  file_path: string | null;
  expires_at: string | null;
  created_at: string;
  updated_at?: string;
  scans?: {
    id: string;
    project_id: string | null;
    project_name: string | null;
    scan_type: string | null;
    file_name: string | null;
    risk_level: string | null;
    total_vulns: number | null;
    files_scanned: number | null;
    created_at: string;
    completed_at: string | null;
    report_storage_path?: string | null;
    report_expires_at?: string | null;
  } | null;
}

export type ScanStreamEvent =
  | { event: "scan_started"; total_files: number; scan_id?: string }
  | { event: "file_started"; file_path: string }
  | { event: "node"; file_path?: string; message: string }
  | { event: "chunks_ready"; file_path: string; total_chunks: number; source_lines?: number; chunker_version?: string; chunks: ChunkOutput[] }
  | { event: "chunk_started"; file_path: string; chunk_index: number; message: string }
  | { event: "model_delta"; file_path: string; chunk_index: number; text: string }
  | { event: "chunk_result"; file_path: string; chunk: ChunkOutput }
  | { event: "correction_started"; file_path: string; chunk_index: number; message: string }
  | { event: "correction_delta"; file_path: string; chunk_index: number; corrected_code: string }
  | { event: "correction_result"; file_path: string; chunk_index: number; corrected_code: string }
  | { event: "scan_result"; result: ScanResult }
  | { event: "error"; status_code?: number; message: string };

// ---------------------------------------------------------------------------
// Scans API
// ---------------------------------------------------------------------------

function uniqueFilesForUpload(files: File[]): File[] {
  const seen = new Set<string>();
  return files.filter((file) => {
    const key = `${file.name}:${file.size}:${file.lastModified}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/**
 * GET /teams/:teamId/github/files?branch=:branch
 * Returns the list of C/C++ file paths available in the given branch.
 */
export async function getBranchFiles(
  teamId: string,
  branch: string
): Promise<string[]> {
  const response = await apiFetch<BranchFilesResponse>(
    `/teams/${teamId}/github/files?branch=${encodeURIComponent(branch)}`
  );
  return response.files;
}

/**
 * POST /teams/:teamId/scans
 * Triggers an AI vulnerability scan on the selected files in the given branch.
 * Returns the full scan result including all vulnerabilities and risk summary.
 */
export async function triggerScan(
  teamId: string,
  branch: string,
  selectedFiles: string[],
  extra?: { project_id?: string; project_name?: string }
): Promise<ScanResult> {
  return apiFetch<ScanResult>(`/teams/${teamId}/scans`, {
    method: "POST",
    body: JSON.stringify({
      branch,
      selected_files: selectedFiles,
      project_id: extra?.project_id ?? "",
      project_name: extra?.project_name ?? "",
    }),
  });
}

export async function triggerGithubScanStream(
  path: string,
  body: Record<string, unknown>,
  onEvent: (event: ScanStreamEvent) => void,
  signal?: AbortSignal,
): Promise<ScanResult> {
  const { supabase } = await import("@/lib/supabase");
  const API_BASE = import.meta.env.VITE_API_URL ?? "http://localhost:8000";
  const { data: { session } } = await supabase.auth.getSession();
  if (!session) throw new Error("Not authenticated");
  const response = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: { Authorization: `Bearer ${session.access_token}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal,
  });
  if (!response.ok || !response.body) {
    const json = await response.json().catch(() => ({}));
    throw new Error(json.detail ?? `Scan failed: ${response.status}`);
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let finalResult: ScanResult | null = null;
  const consume = (raw: string) => {
    if (!raw.trim()) return;
    const event = JSON.parse(raw) as ScanStreamEvent;
    onEvent(event);
    if (event.event === "error") throw new Error(event.message);
    if (event.event === "scan_result") finalResult = event.result;
  };
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split("\n");
    buffer = lines.pop() ?? "";
    lines.forEach(consume);
  }
  consume(buffer);
  if (!finalResult) throw new Error("No scan results returned");
  return finalResult;
}

export async function triggerUploadedFileScan(
  files: File[],
  extra?: { project_id?: string; project_name?: string }
): Promise<ScanResult> {
  const { supabase } = await import("@/lib/supabase");
  const {
    data: { session },
  } = await supabase.auth.getSession();

  if (!session) throw new Error("Not authenticated");

  const API_BASE = import.meta.env.VITE_API_URL ?? "http://localhost:8000";
  const formData = new FormData();
  uniqueFilesForUpload(files).forEach((file) => formData.append("files", file));
  formData.append("project_id", extra?.project_id ?? "");
  formData.append("project_name", extra?.project_name ?? "");

  const response = await fetch(`${API_BASE}/scan/upload-files`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${session.access_token}`,
    },
    body: formData,
  });

  if (!response.ok) {
    const json = await response.json().catch(() => ({}));
    throw new Error(json.detail ?? `Scan failed: ${response.status}`);
  }

  return response.json() as Promise<ScanResult>;
}

export async function triggerUploadedFileScanStream(
  files: File[],
  extra: { project_id?: string; project_name?: string } | undefined,
  onEvent: (event: ScanStreamEvent) => void,
  signal?: AbortSignal
): Promise<ScanResult> {
  const { supabase } = await import("@/lib/supabase");
  const {
    data: { session },
  } = await supabase.auth.getSession();

  if (!session) throw new Error("Not authenticated");

  const API_BASE = import.meta.env.VITE_API_URL ?? "http://localhost:8000";
  const formData = new FormData();
  uniqueFilesForUpload(files).forEach((file) => formData.append("files", file));
  formData.append("project_id", extra?.project_id ?? "");
  formData.append("project_name", extra?.project_name ?? "");

  const response = await fetch(`${API_BASE}/scan/upload-files/stream`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${session.access_token}`,
    },
    body: formData,
    signal,
  });

  if (!response.ok || !response.body) {
    const json = await response.json().catch(() => ({}));
    throw new Error(json.detail ?? `Scan failed: ${response.status}`);
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let finalResult: ScanResult | null = null;

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split("\n");
    buffer = lines.pop() ?? "";
    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (!line) continue;
      const event = JSON.parse(line) as ScanStreamEvent;
      onEvent(event);
      if (event.event === "error") throw new Error(event.message);
      if (event.event === "scan_result") finalResult = event.result;
    }
  }

  const tail = buffer.trim();
  if (tail) {
    const event = JSON.parse(tail) as ScanStreamEvent;
    onEvent(event);
    if (event.event === "error") throw new Error(event.message);
    if (event.event === "scan_result") finalResult = event.result;
  }

  if (!finalResult) throw new Error("No scan results returned");
  return finalResult;
}

/**
 * GET /scans/history
 * Returns all past scans for the current authenticated user.
 */
export async function getScanHistory(): Promise<ScanHistoryItem[]> {
  return apiFetch<ScanHistoryItem[]>("/scans/history");
}

export async function deleteScanHistory(scanId: string): Promise<void> {
  return apiFetch<void>(`/scans/${scanId}`, { method: "DELETE" });
}

export async function cancelScan(scanId: string): Promise<void> {
  return apiFetch<void>(`/scans/${scanId}/cancel`, { method: "POST" });
}

/**
 * GET /scans/:scanId
 * Returns a single scan with its full vulnerability list.
 */
export async function getScanDetail(scanId: string): Promise<ScanDetailResult> {
  return apiFetch<ScanDetailResult>(`/scans/${scanId}`);
}

export async function getScanReportPdf(scanId: string): Promise<Blob> {
  const { supabase } = await import("@/lib/supabase");
  const {
    data: { session },
  } = await supabase.auth.getSession();
  if (!session) throw new Error("Not authenticated");

  const API_BASE = import.meta.env.VITE_API_URL ?? "http://localhost:8000";
  const response = await fetch(`${API_BASE}/scans/${scanId}/report-pdf`, {
    headers: { Authorization: `Bearer ${session.access_token}` },
  });
  if (!response.ok) {
    const json = await response.json().catch(() => ({}));
    throw new Error(json.detail ?? `Report download failed: ${response.status}`);
  }
  return response.blob();
}

export async function listReports(): Promise<ReportItem[]> {
  return apiFetch<ReportItem[]>("/reports");
}

export async function generateReport(payload: {
  report_type: "full";
  project_id: string;
  format: "pdf" | "csv" | "both";
  start_date?: string;
  end_date?: string;
}): Promise<ReportItem[]> {
  return apiFetch<ReportItem[]>("/reports", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function deleteReport(reportId: string): Promise<void> {
  return apiFetch<void>(`/reports/${reportId}`, { method: "DELETE" });
}

async function fetchDownload(path: string): Promise<Response> {
  const { supabase } = await import("@/lib/supabase");
  const API_BASE = import.meta.env.VITE_API_URL ?? "http://localhost:8000";
  const getSessionToken = async () => {
    const { data: { session } } = await supabase.auth.getSession();
    if (session?.access_token) return session.access_token;
    const refreshed = await supabase.auth.refreshSession();
    return refreshed.data.session?.access_token ?? null;
  };
  const request = (accessToken: string) => fetch(`${API_BASE}${path}`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  let accessToken = await getSessionToken();
  if (!accessToken) throw new Error("Not authenticated");
  let response = await request(accessToken);
  if (response.status === 401) {
    const refreshed = await supabase.auth.refreshSession();
    accessToken = refreshed.data.session?.access_token ?? "";
    if (!accessToken) throw new Error("Not authenticated");
    response = await request(accessToken);
  }
  return response;
}

export async function downloadReport(report: ReportItem, format: "pdf" | "csv"): Promise<void> {
  const response = await fetchDownload(`/reports/${report.id}/download?format=${format}`);

  if (!response.ok) {
    const json = await response.json().catch(() => ({}));
    throw new Error(json.detail ?? `Report download failed: ${response.status}`);
  }
  const blob = await response.blob();
  const extension = format;
  const safeName = `${report.name || "secureguard-report"}-${report.id}.${extension}`.replace(/[\\/:*?"<>|]/g, "-");
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = safeName;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

export async function downloadReportCode(report: ReportItem): Promise<void> {
  const response = await fetchDownload(`/reports/${report.id}/download-code`);

  if (!response.ok) {
    const json = await response.json().catch(() => ({}));
    throw new Error(json.detail ?? `Code download failed: ${response.status}`);
  }

  const blob = await response.blob();
  const safeName = `${report.name || "secureguard-report"}-${report.id}-code.zip`.replace(/[\\/:*?"<>|]/g, "-");
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = safeName;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}
