import { apiFetch } from "@/lib/teams-api";
import { BranchFilesResponse, FileContentResponse } from "@/lib/teams-api";
import { ScanResult } from "@/lib/scans-api";
import { supabase } from "@/lib/supabase";

// ---------------------------------------------------------------------------
// Types — mirror the backend Pydantic response schemas exactly
// ---------------------------------------------------------------------------

export interface Project {
  id: string;
  name: string;
  language: string | null;
  health_score: number | null;
  type: "personal" | "team";
  owner_id: string;
  team_id: string | null;
  upload_type: "upload" | "github" | null;
  github_repo: string | null;
  github_branches: string[];
  created_at: string;
  updated_at: string;
}

export interface CreateProjectPayload {
  name: string;
  language?: string;
  type?: "personal" | "team";
  team_id?: string;
  upload_type?: "upload" | "github";
  github_repo?: string;
}

export interface UpdateProjectPayload {
  name?: string;
  language?: string;
  health_score?: number;
  type?: "personal" | "team";
  team_id?: string;
  github_repo?: string;
  upload_type?: "upload" | "github";
}

// Re-export for consumers that import everything from projects-api
export type { BranchFilesResponse, FileContentResponse };

export interface GitHubRepoSummary {
  full_name: string;
  private: boolean;
  url: string;
  default_branch?: string;
  stars?: number;
  forks?: number;
}

// ---------------------------------------------------------------------------
// Projects Cache — avoids re-fetching on every page navigation
// ---------------------------------------------------------------------------
// Simple in-memory cache with a 1-hour TTL. Mutations auto-invalidate it.
// Survives SPA navigation but clears on full page refresh (which is fine).
//
// Realtime invalidation: subscribes to Supabase CDC on the `projects` table.
// Any INSERT/UPDATE/DELETE busts the cache so the next listProjects() call
// fetches fresh data from the API automatically.
// ---------------------------------------------------------------------------

const PROJECTS_CACHE_TTL_MS = 0;

let _projectsCache: { data: Project[]; timestamp: number } | null = null;

/** Clear the projects cache — called after any mutation */
export function invalidateProjectsCache(): void {
  _projectsCache = null;
}

// Subscribe to realtime changes on the projects table so the cache is
// automatically busted whenever data changes (even from another session/tab).
// Set up once at module load time; the subscription is long-lived.
(function setupProjectsCacheInvalidation() {
  if (typeof window === "undefined") return;

  supabase
    .channel("projects-cache-invalidation")
    .on(
      "postgres_changes",
      { event: "*", schema: "public", table: "projects" },
      () => { invalidateProjectsCache(); }
    )
    .subscribe();
})();

// ---------------------------------------------------------------------------
// Projects API — core CRUD
// ---------------------------------------------------------------------------

/** GET /projects — all projects visible to the current user (cached) */
export async function listProjects(): Promise<Project[]> {
  // Return cached data if still fresh
  if (_projectsCache && Date.now() - _projectsCache.timestamp < PROJECTS_CACHE_TTL_MS) {
    return _projectsCache.data;
  }

  const data = await apiFetch<{ projects: Project[] }>("/projects");
  _projectsCache = { data: data.projects, timestamp: Date.now() };
  return data.projects;
}

/** POST /projects — create a new project */
export async function createProject(payload: CreateProjectPayload): Promise<Project> {
  invalidateProjectsCache();
  return apiFetch<Project>("/projects", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

/** PATCH /projects/:id — partial update */
export async function updateProject(
  id: string,
  updates: UpdateProjectPayload
): Promise<Project> {
  invalidateProjectsCache();
  return apiFetch<Project>(`/projects/${id}`, {
    method: "PATCH",
    body: JSON.stringify(updates),
  });
}

/** DELETE /projects/:id — single delete */
export async function deleteProject(id: string): Promise<void> {
  invalidateProjectsCache();
  return apiFetch<void>(`/projects/${id}`, { method: "DELETE" });
}

/** DELETE /projects/bulk-delete — vectorized delete, returns count */
export async function bulkDeleteProjects(
  ids: string[]
): Promise<{ deleted: number }> {
  invalidateProjectsCache();
  return apiFetch<{ deleted: number }>("/projects/bulk-delete", {
    method: "DELETE",
    body: JSON.stringify({ ids }),
  });
}

// ---------------------------------------------------------------------------
// Projects API — GitHub integration (OAuth / GitHub App flow)
// ---------------------------------------------------------------------------
// Mirrors the team GitHub flow exactly:
//   1. getProjectGithubAuthorizeUrl  → redirect browser to GitHub App install
//   2. (GitHub redirects back)       → /projects/github/callback handled by backend
//   3. listProjectGithubRepos        → list repos from installation token
//   4. selectProjectGithubRepo       → store repo + branches (no PAT)
//   5. syncProjectGithubBranches     → re-sync branches (no PAT)
//
// Disconnect: updateProject with { github_repo: "" }
// ---------------------------------------------------------------------------

/** GET /projects/:projectId/github/authorize — get GitHub App install URL */
export async function getProjectGithubAuthorizeUrl(projectId: string): Promise<string> {
  const data = await apiFetch<{ authorization_url: string }>(
    `/projects/${projectId}/github/authorize`
  );
  return data.authorization_url;
}

export async function getPersonalGithubAuthorizeUrl(): Promise<string> {
  const data = await apiFetch<{ authorization_url: string }>("/projects/github/personal/authorize");
  return data.authorization_url;
}

export async function listPersonalGithubRepos(
  installationId: number
): Promise<GitHubRepoSummary[]> {
  const data = await apiFetch<{ repos: GitHubRepoSummary[] }>(
    `/projects/github/personal/repos?installation_id=${encodeURIComponent(String(installationId))}`
  );
  return data.repos;
}

export async function listPersonalGithubBranches(
  installationId: number,
  repoFullName: string
): Promise<string[]> {
  const params = new URLSearchParams({
    installation_id: String(installationId),
    repo: repoFullName,
  });
  const data = await apiFetch<{ branches: string[] }>(`/projects/github/personal/branches?${params.toString()}`);
  return data.branches;
}

export async function fetchPersonalGithubFiles(
  installationId: number,
  repoFullName: string,
  branch: string
): Promise<BranchFilesResponse> {
  const params = new URLSearchParams({
    installation_id: String(installationId),
    repo: repoFullName,
    branch,
  });
  return apiFetch<BranchFilesResponse>(`/projects/github/personal/files?${params.toString()}`);
}

/** GET /projects/:projectId/github/repos — list repos from stored installation token */
export async function listProjectGithubRepos(
  projectId: string
): Promise<{ full_name: string; private: boolean; url: string }[]> {
  const data = await apiFetch<{
    repos: { full_name: string; private: boolean; url: string }[];
  }>(`/projects/${projectId}/github/repos`);
  return data.repos;
}

/** POST /projects/:projectId/github/select-repo — store repo + fetch branches via installation token */
export async function selectProjectGithubRepo(
  projectId: string,
  repoFullName: string,
  repoUrl: string
): Promise<Project> {
  invalidateProjectsCache();
  return apiFetch<Project>(`/projects/${projectId}/github/select-repo`, {
    method: "POST",
    body: JSON.stringify({ repo_full_name: repoFullName, repo_url: repoUrl }),
  });
}

/** POST /projects/:projectId/github/sync-branches — re-sync without PAT */
export async function syncProjectGithubBranches(projectId: string): Promise<Project> {
  invalidateProjectsCache();
  return apiFetch<Project>(`/projects/${projectId}/github/sync-branches`, {
    method: "POST",
  });
}

// ---------------------------------------------------------------------------
// Projects API — GitHub integration (PAT-based, legacy / private repos)
// ---------------------------------------------------------------------------
// The PAT is passed through to the backend for each call and is never stored
// server-side. For GET endpoints that cannot carry a request body, the PAT
// is sent as a query parameter (transmitted over HTTPS, not logged by default).
// ---------------------------------------------------------------------------

/**
 * POST /projects/:projectId/github
 * Connect a GitHub repository to a personal project using a PAT.
 * Validates the repo, fetches all branches, persists both.
 * The PAT is discarded by the backend immediately after use.
 */
export async function connectProjectGithub(
  projectId: string,
  repoUrl: string,
  pat: string
): Promise<Project> {
  invalidateProjectsCache();
  return apiFetch<Project>(`/projects/${projectId}/github`, {
    method: "POST",
    body: JSON.stringify({ repo_url: repoUrl, pat }),
  });
}

/**
 * POST /projects/:projectId/github/refresh
 * Re-fetch the branch list for the project's connected repository.
 * Accepts an updated repoUrl or PAT if they have changed.
 */
export async function refreshProjectGithubBranches(
  projectId: string,
  repoUrl: string,
  pat: string
): Promise<Project> {
  invalidateProjectsCache();
  return apiFetch<Project>(`/projects/${projectId}/github/refresh`, {
    method: "POST",
    body: JSON.stringify({ repo_url: repoUrl, pat }),
  });
}

/**
 * GET /projects/:projectId/branches/:branch/files
 * Return the full recursive file tree for a branch.
 * Uses the stored installation token — no PAT needed after OAuth connect.
 */
export async function fetchProjectBranchFiles(
  projectId: string,
  branch: string,
  pat?: string
): Promise<BranchFilesResponse> {
  const query = pat ? `?pat=${encodeURIComponent(pat)}` : "";
  return apiFetch<BranchFilesResponse>(
    `/projects/${projectId}/branches/${encodeURIComponent(branch)}/files${query}`
  );
}

/**
 * GET /projects/:projectId/branches/:branch/files/content
 * Fetch and decode the content of a single file from a branch.
 * Uses the stored installation token — no PAT needed after OAuth connect.
 */
export async function fetchProjectFileContent(
  projectId: string,
  branch: string,
  filePath: string,
  pat?: string
): Promise<FileContentResponse> {
  const params = new URLSearchParams({ path: filePath });
  if (pat) params.set("pat", pat);
  return apiFetch<FileContentResponse>(
    `/projects/${projectId}/branches/${encodeURIComponent(branch)}/files/content?${params.toString()}`
  );
}

export async function fetchPersonalGithubFileContent(
  installationId: number,
  repo: string,
  branch: string,
  filePath: string
): Promise<FileContentResponse> {
  const params = new URLSearchParams({
    installation_id: String(installationId),
    repo,
    branch,
    path: filePath,
  });
  return apiFetch<FileContentResponse>(`/projects/github/personal/files/content?${params.toString()}`);
}

/**
 * POST /projects/:projectId/scans
 * Fetch selected files from GitHub and run the vulnerability scanner.
 * Uses the stored installation token — no PAT needed after OAuth connect.
 */
export async function triggerProjectScan(
  projectId: string,
  branch: string,
  selectedFiles: string[],
  extra?: { project_id?: string; project_name?: string; installation_id?: number; repo_full_name?: string }
): Promise<ScanResult> {
  return apiFetch<ScanResult>(
    `/projects/${projectId}/scans`,
    {
      method: "POST",
      body: JSON.stringify({
        branch,
        selected_files: selectedFiles,
        project_id: extra?.project_id ?? projectId,
        project_name: extra?.project_name ?? "",
        installation_id: extra?.installation_id,
        repo_full_name: extra?.repo_full_name,
      }),
    }
  );
}
