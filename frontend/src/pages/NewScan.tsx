import { useState, useEffect, useCallback, useRef, Fragment, type Dispatch, type SetStateAction } from "react";
import { useSearchParams } from "react-router-dom";
import DashboardLayout from "@/components/dashboard/DashboardLayout";
import { useCurrentUser } from "@/hooks/use-current-user";
import {
  getBranchFiles,
  triggerUploadedFileScan,
  triggerUploadedFileScanStream,
  triggerGithubScanStream,
  ScanResult,
  VulnerabilityDetail,
  ScanStreamEvent,
  ChunkOutput,
} from "@/lib/scans-api";
import {
  listProjects,
  createProject,
  deleteProject,
  getPersonalGithubAuthorizeUrl,
  listPersonalGithubRepos,
  listPersonalGithubBranches,
  fetchPersonalGithubFiles,
  fetchPersonalGithubFileContent,
  type GitHubRepoSummary,
} from "@/lib/projects-api";
import { fetchBranchFiles, fetchFileContent as fetchTeamFileContent, listTeams } from "@/lib/teams-api";
import type { Team as ApiTeam, BranchFileItem } from "@/lib/teams-api";
import {
  listProjectFiles,
  listProjectSourceFiles,
  formatFileSize,
  formatRelativeTime,
  type ProjectFileResponse,
} from "@/lib/project-files-api";
import { useQuery } from "@tanstack/react-query";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Command, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList } from "@/components/ui/command";
import {
  Upload,
  Github,
  Play,
  Shield,
  ArrowLeft,
  StopCircle,
  PanelLeftClose,
  PanelLeft,
  Lock,
  Info,
  Plus,
  Crown,
  Users,
  Eye,
  RefreshCw,
  Search,
  Check,
  ChevronsUpDown,
  AlertTriangle,
  Boxes,
  BrainCircuit,
  Clock3,
  FileUp,
  Radar,
  Sparkles,
  Loader2,
  Star,
  GitFork,
  GitBranch,
  Filter,
  FileText,
  Unplug,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { CodeViewer } from "@/components/scan/CodeViewer";
import { ScanningProgress } from "@/components/scan/ScanningProgress";

const LIVE_SCAN_STATE_KEY = "secureguard.liveScanView";
const LIVE_SCAN_STATE_EVENT = "secureguard:live-scan-state";

const readLiveScanField = <T,>(field: string, fallback: T): T => {
  try {
    const value = JSON.parse(window.sessionStorage.getItem(LIVE_SCAN_STATE_KEY) || "{}")[field];
    return value === undefined ? fallback : value as T;
  } catch {
    return fallback;
  }
};

const useLiveScanState = <T,>(field: string, initialValue: T): [T, Dispatch<SetStateAction<T>>] => {
  const [value, setValue] = useState<T>(() => readLiveScanField(field, initialValue));

  useEffect(() => {
    const sync = (event: Event) => {
      const detail = (event as CustomEvent<{ field: string; value: T }>).detail;
      if (detail?.field === field) setValue(detail.value);
    };
    window.addEventListener(LIVE_SCAN_STATE_EVENT, sync);
    return () => window.removeEventListener(LIVE_SCAN_STATE_EVENT, sync);
  }, [field]);

  const update = useCallback<Dispatch<SetStateAction<T>>>((nextValue) => {
    // Persist before asking React to render. Scan requests intentionally keep
    // running after this page unmounts, and React may ignore an updater queued
    // for an unmounted component. Writing here preserves streamed/final data so
    // reopening the scan restores vulnerabilities and corrected code.
    const current = readLiveScanField(field, initialValue);
    const resolved = typeof nextValue === "function"
      ? (nextValue as (previous: T) => T)(current)
      : nextValue;
    try {
      const stored = JSON.parse(window.sessionStorage.getItem(LIVE_SCAN_STATE_KEY) || "{}");
      window.sessionStorage.setItem(LIVE_SCAN_STATE_KEY, JSON.stringify({ ...stored, [field]: resolved }));
    } catch {
      // The in-memory state still works if browser storage is unavailable.
    }
    setValue(resolved);
    window.dispatchEvent(new CustomEvent(LIVE_SCAN_STATE_EVENT, { detail: { field, value: resolved } }));
  }, [field, initialValue]);

  return [value, update];
};

const clearLiveScanState = () => window.sessionStorage.removeItem(LIVE_SCAN_STATE_KEY);
import { FileUploadArea } from "@/components/scan/FileUploadArea";
import { toast } from "sonner";
import { addLocalNotification, getNotificationPreferences } from "@/lib/notifications";
import {
  completeGlobalScanActivity,
  failGlobalScanActivity,
  startGlobalScanActivity,
  updateGlobalScanActivity,
} from "@/lib/scan-activity";

interface CodeLine {
  lineNumber: number;
  content: string;
  status: "pending" | "scanning" | "safe" | "vulnerable";
  vulnerability?: string;
}

type ThinkingEventType = "info" | "warning" | "error" | "success";

const splitSourceLines = (source: string): string[] => {
  const lines = source.replace(/\r+\n/g, "\n").replace(/\r/g, "\n").split("\n");
  while (lines.length > 1 && lines[lines.length - 1] === "") {
    lines.pop();
  }
  return lines.length > 0 ? lines : [""];
};

const previewFunctionName = (filePath: string): string => {
  const baseName = filePath.split(/[\\/]/).pop() ?? "source";
  return baseName.replace(/\.[^.]+$/, "").replace(/[^A-Za-z0-9_]/g, "_") || "source";
};

const buildQueuedSourcePreview = (filePaths: string[]): CodeLine[] => {
  const lines: CodeLine[] = [];
  filePaths.slice(0, 6).forEach((filePath, fileIndex) => {
    const name = previewFunctionName(filePath);
    const ext = extensionOf(filePath);
    const sourcePreview = ext === ".zip"
      ? [
          `// ${filePath}`,
          "// ZIP archive queued; backend will extract C/C++ sources",
          "int extracted_sources = 0;",
          "while (archive_has_next_entry()) {",
          "    extracted_sources += scan_if_supported_source();",
          "}",
        ]
      : [
          `// ${filePath}`,
          "#include <stdio.h>",
          `int ${name}_security_review(void) {`,
          "    char input[256];",
          "    fgets(input, sizeof(input), stdin);",
          "    return validate_source_path(input);",
          "}",
        ];

    if (fileIndex > 0) lines.push({ lineNumber: lines.length + 1, content: "", status: "pending" });
    sourcePreview.forEach((content) => {
      lines.push({ lineNumber: lines.length + 1, content, status: "pending" });
    });
  });
  return lines.length > 0 ? lines : [{ lineNumber: 1, content: "// Waiting for source files...", status: "pending" }];
};

const codeLinesFromSource = (source: string): CodeLine[] =>
  splitSourceLines(source).map((content, index) => ({
    lineNumber: index + 1,
    content,
    status: "pending" as const,
  }));

const ZIP_NO_SOURCE_MESSAGE =
  "This ZIP does not contain any C or C++ source files. Please upload a ZIP with .c, .cpp, .h, .hpp, .cc, .cxx, or .hxx files.";

const SOURCE_EXTENSIONS = [".c", ".h", ".cpp", ".cxx", ".cc", ".hpp", ".hxx"];
const C_EXTENSIONS = [".c", ".h"];
const CPP_EXTENSIONS = [".cpp", ".cxx", ".cc", ".hpp", ".hxx"];
const SHARED_GITHUB_INSTALLATION_KEY = "secureguard_github_installation_id";
const LEGACY_PERSONAL_GITHUB_INSTALLATION_KEY = "secureguard_personal_github_installation_id";

const extensionOf = (filename: string): string => {
  const dotIndex = filename.lastIndexOf(".");
  return dotIndex === -1 ? "" : filename.slice(dotIndex).toLowerCase();
};

const isGithubSourcePath = (path: string): boolean => SOURCE_EXTENSIONS.includes(extensionOf(path));
const isGithubScannablePath = (path: string): boolean => isGithubSourcePath(path) || extensionOf(path) === ".zip";

const githubLanguageLabel = (path: string): string => {
  const ext = extensionOf(path);
  if (C_EXTENSIONS.includes(ext)) return "C";
  if (CPP_EXTENSIONS.includes(ext)) return "C++";
  if (ext === ".zip") return "ZIP";
  if (ext === ".md") return "Markdown";
  if (ext === ".py") return "Python";
  if ([".js", ".jsx", ".ts", ".tsx"].includes(ext)) return "JS";
  return "Other";
};

const githubLanguageBadgeClass = (label: string): string => {
  if (label === "C") return "bg-purple-500/20 text-purple-300 border-purple-500/30";
  if (label === "C++") return "bg-pink-500/20 text-pink-300 border-pink-500/30";
  return "bg-muted text-muted-foreground border-border/50";
};

const friendlyScanError = (message: string): string => {
  if (message.toLowerCase().includes("does not contain any c or c++ source files")) {
    return ZIP_NO_SOURCE_MESSAGE;
  }
  if (message.toLowerCase().includes("suspicious file name found")) {
    return message;
  }
  return message;
};

const isRenameFileError = (message: string): boolean =>
  message.toLowerCase().includes("suspicious file name found");

const getChunkReportTitle = (chunks: ChunkOutput[]): string => {
  const zipFolderName = chunks
    .map((chunk) => chunk.file_path ?? "")
    .find((filePath) => filePath.includes("/"))
    ?.split("/")[0]
    ?.trim();
  return zipFolderName || "Source Files";
};

const sourceLineForVulnerability = (chunk: ChunkOutput, vulnerability: VulnerabilityDetail): string => {
  const codeLines = splitSourceLines(chunk.code ?? "");
  const absoluteLine = vulnerability.line_number || vulnerability.absolute_line || 0;
  if (absoluteLine >= chunk.start_line && absoluteLine <= chunk.end_line) {
    return codeLines[absoluteLine - chunk.start_line] ?? "";
  }
  if (vulnerability.line_number > 0 && vulnerability.line_number <= codeLines.length) {
    return codeLines[vulnerability.line_number - 1] ?? "";
  }
  return "";
};

const codeForVulnerability = (chunk: ChunkOutput, vulnerability: VulnerabilityDetail): string => {
  const affectedCode = vulnerability.affected_code?.trim();
  if (affectedCode) return affectedCode;
  return sourceLineForVulnerability(chunk, vulnerability).trim() || `Line ${vulnerability.line_number || vulnerability.absolute_line || "N/A"}`;
};

const NumberedCodeBlock = ({
  code,
  startLine = 1,
  emptyText = "No code returned.",
}: {
  code?: string;
  startLine?: number;
  emptyText?: string;
}) => {
  const lines = splitSourceLines(code?.trimEnd() ? code : emptyText);
  return (
    <div className="mt-2 max-h-[420px] overflow-auto rounded-md border border-border/50 bg-[#0d1117] text-sm leading-relaxed text-foreground">
      <table className="w-full border-collapse font-mono">
        <tbody>
          {lines.map((line, index) => (
            <tr key={`${index}-${line}`}>
              <td className="w-10 min-w-10 max-w-10 select-none border-r border-white/10 bg-white/[0.03] px-2 py-0.5 text-right align-top text-xs text-muted-foreground">
                {startLine + index}
              </td>
              <td className="whitespace-pre px-4 py-0.5 align-top">{line || " "}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

const parseThinkingStep = (step: string) => {
  const match = step.match(/^\[(\d{2}:\d{2})\]\s+([^:]+):\s+(.*)$/);
  if (!match) {
    return { time: "", type: "Working", message: step };
  }
  return { time: match[1], type: match[2], message: match[3] };
};

const formatElapsedClock = (elapsedSeconds: number): string => {
  const safeSeconds = Math.max(0, Math.floor(elapsedSeconds));
  const minutes = Math.floor(safeSeconds / 60);
  const seconds = safeSeconds % 60;
  return `${minutes.toString().padStart(2, "0")}:${seconds.toString().padStart(2, "0")}`;
};

const getThinkingStyle = (message: string, type: string) => {
  const text = `${type} ${message}`.toLowerCase();
  if (type.toLowerCase().includes("error")) {
    return {
      label: "Attention",
      icon: AlertTriangle,
      className: "border-destructive/35 bg-destructive/10 text-destructive",
      dotClassName: "bg-destructive",
    };
  }
  if (text.includes("upload") || text.includes("source") || text.includes("file") || text.includes("package")) {
    return {
      label: "Intake",
      icon: FileUp,
      className: "border-blue-500/30 bg-blue-500/10 text-blue-300",
      dotClassName: "bg-blue-400",
    };
  }
  if (text.includes("chunk") || text.includes("static") || text.includes("review") || text.includes("vulnerab")) {
    return {
      label: "Analysis",
      icon: Radar,
      className: "border-amber-500/30 bg-amber-500/10 text-amber-300",
      dotClassName: "bg-amber-400",
    };
  }
  if (text.includes("done") || text.includes("saved") || text.includes("complete") || text.includes("assembled") || text.includes("corrected")) {
    return {
      label: "Verdict",
      icon: Check,
      className: "border-emerald-500/30 bg-emerald-500/10 text-emerald-300",
      dotClassName: "bg-emerald-400",
    };
  }
  return {
    label: "Node",
    icon: BrainCircuit,
    className: "border-primary/30 bg-primary/10 text-primary",
    dotClassName: "bg-primary",
  };
};

const NewScan = () => {
  const [searchParams] = useSearchParams();
  const autoStartRef = useRef(false);
  const [activeTab, setActiveTab] = useState("upload");
  const [isScanning, setIsScanning] = useLiveScanState("isScanning", false);
  const [scanComplete, setScanComplete] = useLiveScanState("scanComplete", false);
  const [showLiveScan, setShowLiveScan] = useLiveScanState("showLiveScan", true);
  const [isDragOver, setIsDragOver] = useState(false);
  const [uploadedFiles, setUploadedFiles] = useState<File[]>([]);
  const [fileContent, setFileContent] = useState<string>("");
  const [branch, setBranch] = useState("main");
  
  // New state for team-aware scanning
  const [projectName, setProjectName] = useState("");
  const [scanMode, setScanMode] = useState<"personal" | "team">("personal");
  const [selectedTeamId, setSelectedTeamId] = useState<string>("");

  // Project selector state
  const [selectedProjectId, setSelectedProjectId] = useState<string>("");
  const [selectedProjectName, setSelectedProjectName] = useState<string>("");
  // "new" means user wants to create a new project inline
  const [newProjectName, setNewProjectName] = useState<string>("");
  const [isCreatingProject, setIsCreatingProject] = useState(false);
  const [isProjectSubmitting, setIsProjectSubmitting] = useState(false);
  const [projectSearch, setProjectSearch] = useState("");
  const [projectDropdownOpen, setProjectDropdownOpen] = useState(false);

  // ── Project file list state (personal mode) ──────────────────────────────
  const [projectFiles, setProjectFiles] = useState<ProjectFileResponse[]>([]);
  const [projectFilesLoading, setProjectFilesLoading] = useState(false);
  const [projectFilesError, setProjectFilesError] = useState<string>("");
  const [autoRescanPreparing, setAutoRescanPreparing] = useState(false);
  // Set of file IDs that are checked for scanning
  const [selectedFileIds, setSelectedFileIds] = useState<Set<string>>(new Set());
  const [saveToProject, setSaveToProject] = useState<Record<number, boolean>>({});
  const [githubInstallationId, setGithubInstallationId] = useState<number | null>(null);
  const [githubRepos, setGithubRepos] = useState<GitHubRepoSummary[]>([]);
  const [githubReposLoading, setGithubReposLoading] = useState(false);
  const [githubReposError, setGithubReposError] = useState("");
  const [selectedGithubRepoName, setSelectedGithubRepoName] = useState("");
  const [githubBranches, setGithubBranches] = useState<string[]>([]);
  const [githubBranchesLoading, setGithubBranchesLoading] = useState(false);
  const [githubFiles, setGithubFiles] = useState<BranchFileItem[]>([]);
  const [githubFilesLoading, setGithubFilesLoading] = useState(false);
  const [githubFilesError, setGithubFilesError] = useState("");
  const [githubFileSearch, setGithubFileSearch] = useState("");
  const [githubFileFilter, setGithubFileFilter] = useState<"all" | "source">("all");
  const [selectedGithubFiles, setSelectedGithubFiles] = useState<Set<string>>(new Set());
  const [teamGithubFiles, setTeamGithubFiles] = useState<BranchFileItem[]>([]);
  const [teamGithubFilesLoading, setTeamGithubFilesLoading] = useState(false);
  const [teamGithubFilesError, setTeamGithubFilesError] = useState("");
  const [selectedTeamGithubFiles, setSelectedTeamGithubFiles] = useState<Set<string>>(new Set());
  // Per-uploaded-file "save to project" toggle: index → boolean

  // Fetch projects for the selector
  const { data: projects = [], refetch: refetchProjects } = useQuery({
    queryKey: ["projects"],
    queryFn: listProjects,
  });

  // Fetch real teams the user belongs to
  const { data: allTeams = [] } = useQuery({
    queryKey: ["teams"],
    queryFn: listTeams,
  });

  // The selected project object (if any)
  const selectedProject = projects.find((p) => p.id === selectedProjectId) ?? null;
  const selectedGithubRepo = githubRepos.find((repo) => repo.full_name === selectedGithubRepoName) ?? null;

  const githubSourceFiles = githubFiles.filter((file) => file.type === "file" && isGithubScannablePath(file.path));
  const filteredGithubFiles = githubFiles.filter((file) => {
    const matchesSearch = !githubFileSearch.trim() || file.path.toLowerCase().includes(githubFileSearch.trim().toLowerCase());
    const matchesFilter = githubFileFilter === "all" || isGithubScannablePath(file.path);
    return matchesSearch && matchesFilter;
  });

  const selectedGithubLanguage: "C" | "C++" | "C, C++" | null = (() => {
    const selected = githubFiles.filter((file) => selectedGithubFiles.has(file.path));
    const hasC = selected.some((file) => C_EXTENSIONS.includes(extensionOf(file.path)));
    const hasCpp = selected.some((file) => CPP_EXTENSIONS.includes(extensionOf(file.path)));
    if (hasC && hasCpp) return "C, C++";
    if (hasCpp) return "C++";
    if (hasC) return "C";
    return null;
  })();

  const teamGithubSourceFiles = teamGithubFiles.filter((file) => file.type === "file" && isGithubScannablePath(file.path));
  const selectedTeamGithubLanguage: "C" | "C++" | "C, C++" | null = (() => {
    const selected = teamGithubFiles.filter((file) => selectedTeamGithubFiles.has(file.path));
    const hasC = selected.some((file) => C_EXTENSIONS.includes(extensionOf(file.path)));
    const hasCpp = selected.some((file) => CPP_EXTENSIONS.includes(extensionOf(file.path)));
    if (hasC && hasCpp) return "C, C++";
    if (hasCpp) return "C++";
    if (hasC) return "C";
    return null;
  })();

  const loadGithubRepos = useCallback(async (installationId: number) => {
    setGithubReposLoading(true);
    setGithubReposError("");
    try {
      const repos = await listPersonalGithubRepos(installationId);
      setGithubRepos(repos);
      if (!selectedGithubRepoName && repos.length > 0) {
        setSelectedGithubRepoName(repos[0].full_name);
      }
    } catch (err: any) {
      setGithubReposError(err.message || "Failed to load GitHub repositories");
    } finally {
      setGithubReposLoading(false);
    }
  }, [selectedGithubRepoName]);

  const handleConnectGithub = async () => {
    try {
      const url = await getPersonalGithubAuthorizeUrl();
      window.location.href = url;
    } catch (err: any) {
      toast.error("Failed to start GitHub connection", { description: err.message || "Please try again." });
    }
  };

  const handleDisconnectGithub = () => {
    window.localStorage.removeItem(SHARED_GITHUB_INSTALLATION_KEY);
    window.sessionStorage.removeItem(LEGACY_PERSONAL_GITHUB_INSTALLATION_KEY);
    setGithubInstallationId(null);
    setGithubRepos([]);
    setGithubReposError("");
    setSelectedGithubRepoName("");
    setGithubBranches([]);
    setBranch("main");
    setGithubFiles([]);
    setGithubFilesError("");
    setGithubFileSearch("");
    setGithubFileFilter("all");
    setSelectedGithubFiles(new Set());
    window.history.replaceState({}, "", "/new-scan");
    toast.success("GitHub disconnected", {
      description: "You can now connect a different GitHub account.",
    });
  };

  // If the selected project belongs to a team, fetch that team's GitHub info
  // ── Fetch project files whenever a real project is selected ──────────────
  const fetchProjectFiles = useCallback(async (projectId: string) => {
    if (!projectId || projectId === "__new__") return;
    setProjectFilesLoading(true);
    setProjectFilesError("");
    try {
      const files = await listProjectFiles(projectId);
      setProjectFiles(files);
      // Default: select all files
      setSelectedFileIds(new Set(files.map((f) => f.id)));
    } catch (err: any) {
      setProjectFilesError(err.message || "Failed to load project files");
      setProjectFiles([]);
    } finally {
      setProjectFilesLoading(false);
    }
  }, []);

  useEffect(() => {
    if (selectedProjectId && selectedProjectId !== "__new__") {
      fetchProjectFiles(selectedProjectId);
    } else {
      setProjectFiles([]);
      setSelectedFileIds(new Set());
    }
  }, [selectedProjectId, fetchProjectFiles]);

  useEffect(() => {
    const installationFromUrl = searchParams.get("github_installation_id");
    const storedInstallation =
      window.localStorage.getItem(SHARED_GITHUB_INSTALLATION_KEY) ||
      window.sessionStorage.getItem(LEGACY_PERSONAL_GITHUB_INSTALLATION_KEY);
    const rawInstallation = installationFromUrl || storedInstallation;
    const parsedInstallation = rawInstallation ? Number(rawInstallation) : NaN;
    if (Number.isFinite(parsedInstallation) && parsedInstallation > 0) {
      setGithubInstallationId(parsedInstallation);
      window.localStorage.setItem(SHARED_GITHUB_INSTALLATION_KEY, String(parsedInstallation));
      window.sessionStorage.setItem(LEGACY_PERSONAL_GITHUB_INSTALLATION_KEY, String(parsedInstallation));
      setActiveTab("github");
      if (installationFromUrl) {
        toast.success("GitHub connected", {
          description: "Select a repository, branch, and files to scan.",
        });
      }
    }
  }, [searchParams]);

  useEffect(() => {
    const githubError = searchParams.get("github_error");
    if (!githubError) return;
    setActiveTab("github");
    toast.error("GitHub connection failed", {
      description: githubError === "no_installation"
        ? "SecureGuard Pro could not find an installed GitHub App for this account."
        : "Please try connecting GitHub again.",
    });
  }, [searchParams]);

  useEffect(() => {
    if (!githubInstallationId) return;
    loadGithubRepos(githubInstallationId);
  }, [githubInstallationId, loadGithubRepos]);

  useEffect(() => {
    if (!githubInstallationId || !selectedGithubRepo) {
      setGithubBranches([]);
      setGithubFiles([]);
      setSelectedGithubFiles(new Set());
      return;
    }
    let cancelled = false;
    setGithubBranchesLoading(true);
    listPersonalGithubBranches(githubInstallationId, selectedGithubRepo.full_name)
      .then((branches) => {
        if (cancelled) return;
        setGithubBranches(branches);
        const nextBranch = branches.includes(selectedGithubRepo.default_branch || "")
          ? selectedGithubRepo.default_branch!
          : branches[0] || "main";
        setBranch(nextBranch);
      })
      .catch((err: any) => {
        if (!cancelled) toast.error("Failed to load branches", { description: err.message || "Please try again." });
      })
      .finally(() => {
        if (!cancelled) setGithubBranchesLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [githubInstallationId, selectedGithubRepo]);

  useEffect(() => {
    if (!githubInstallationId || !selectedGithubRepo || !branch) return;
    let cancelled = false;
    setGithubFilesLoading(true);
    setGithubFilesError("");
    fetchPersonalGithubFiles(githubInstallationId, selectedGithubRepo.full_name, branch)
      .then((response) => {
        if (cancelled) return;
        setGithubFiles(response.files);
        const sourcePaths = response.files
          .filter((file) => file.type === "file" && isGithubScannablePath(file.path))
          .map((file) => file.path);
        setSelectedGithubFiles(new Set(sourcePaths));
      })
      .catch((err: any) => {
        if (!cancelled) {
          setGithubFilesError(err.message || "Failed to load GitHub files");
          setGithubFiles([]);
          setSelectedGithubFiles(new Set());
        }
      })
      .finally(() => {
        if (!cancelled) setGithubFilesLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [githubInstallationId, selectedGithubRepo, branch]);

  useEffect(() => {
    const rescanProjectId = searchParams.get("projectId");
    if (!rescanProjectId || projects.length === 0 || selectedProjectId) return;
    const project = projects.find((item) => item.id === rescanProjectId);
    if (!project) return;
    setScanMode(project.type === "team" ? "team" : "personal");
    setSelectedProjectId(project.id);
    setSelectedProjectName(project.name);
    setProjectName(project.name);
    if (project.team_id) setSelectedTeamId(project.team_id);
    setActiveTab("upload");
  }, [projects, searchParams, selectedProjectId]);

  useEffect(() => {
    if (searchParams.get("autoStart") !== "1" || autoStartRef.current || isScanning) return;
    if (!selectedProjectId || selectedProjectId === "__new__" || projectFilesLoading || selectedFileIds.size === 0) return;
    autoStartRef.current = true;
    handleStartScan();
  }, [searchParams, selectedProjectId, projectFilesLoading, selectedFileIds.size, isScanning]);

  const handleCreateInlineProject = async () => {
    const trimmedName = newProjectName.trim();
    if (!trimmedName) {
      toast.error("Project name is required");
      return null;
    }
    if (!/^[a-zA-Z]/.test(trimmedName)) {
      toast.error("Invalid Project Name", { description: "Project name must start with a letter." });
      return null;
    }

    setIsProjectSubmitting(true);
    try {
      const created = await createProject({
        name: trimmedName,
        type: scanMode,
        language: activeTab === "github"
          ? (isTeamMode ? selectedTeamGithubLanguage ?? undefined : selectedGithubLanguage ?? undefined)
          : detectedProjectLanguage ?? undefined,
        upload_type: activeTab === "github" ? "github" : "upload",
        github_repo: activeTab === "github" ? (isTeamMode ? selectedApiTeam?.github_repo ?? undefined : selectedGithubRepo?.url) : undefined,
        team_id: scanMode === "team" ? selectedTeamId : undefined,
      });
      setSelectedProjectId(created.id);
      setSelectedProjectName(created.name);
      setProjectName(created.name);
      setNewProjectName("");
      setIsCreatingProject(false);
      await refetchProjects();
      toast.success("Project created", { description: created.name });
      return created;
    } catch (err: any) {
      toast.error("Failed to create project", { description: err.message || "Please try again." });
      return null;
    } finally {
      setIsProjectSubmitting(false);
    }
  };

  // Selected team in team mode (real API team)
  const selectedApiTeam: ApiTeam | null = allTeams.find((t) => t.id === selectedTeamId) ?? null;
  const userTeamRole = selectedApiTeam?.current_user_role ?? null;
  const isViewer = userTeamRole === "viewer";
  const canScanInTeam = userTeamRole === "admin" || userTeamRole === "developer";
  const isTeamMode = scanMode === "team";

  // Current authenticated user — needed to resolve assigned branches
  const { user: currentUser } = useCurrentUser();

  // Branches visible to the current user for the selected team:
  // - admin  → all branches
  // - developer → only their assigned branches
  // - viewer → no branches (scan blocked anyway)
  const visibleTeamBranches: string[] = (() => {
    if (!selectedApiTeam?.github_branches?.length) return [];
    if (userTeamRole === "admin") return selectedApiTeam.github_branches;
    if (userTeamRole === "developer" && currentUser?.id) {
      const myMember = selectedApiTeam.members.find((m) => m.user_id === currentUser.id);
      const assigned = myMember?.branches ?? [];
      // Only show branches that exist in the synced branch list
      return assigned.filter((b) => selectedApiTeam.github_branches.includes(b));
    }
    return [];
  })();

  useEffect(() => {
    if (!isTeamMode || activeTab !== "github" || !selectedApiTeam?.github_repo) {
      setTeamGithubFiles([]);
      setSelectedTeamGithubFiles(new Set());
      setTeamGithubFilesError("");
      return;
    }

    const savedTeamBranch = window.localStorage.getItem(`secureguard_team_branch_${selectedApiTeam.id}`);
    const nextBranch = savedTeamBranch && selectedApiTeam.github_branches.includes(savedTeamBranch)
      ? savedTeamBranch
      : branch && selectedApiTeam.github_branches.includes(branch)
      ? branch
      : selectedApiTeam.github_branches[0] || "";

    if (!nextBranch) {
      setTeamGithubFiles([]);
      setSelectedTeamGithubFiles(new Set());
      return;
    }

    if (branch !== nextBranch) {
      setBranch(nextBranch);
      return;
    }

    let cancelled = false;
    setTeamGithubFilesLoading(true);
    setTeamGithubFilesError("");
    fetchBranchFiles(selectedApiTeam.id, nextBranch)
      .then((response) => {
        if (cancelled) return;
        setTeamGithubFiles(response.files);
        setSelectedTeamGithubFiles(new Set());
      })
      .catch((err: any) => {
        if (cancelled) return;
        setTeamGithubFiles([]);
        setSelectedTeamGithubFiles(new Set());
        setTeamGithubFilesError(err.message || "Failed to load team branch files");
      })
      .finally(() => {
        if (!cancelled) setTeamGithubFilesLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [activeTab, branch, isTeamMode, selectedApiTeam?.github_repo, selectedApiTeam?.github_branches, selectedApiTeam?.id]);
   
  // Scanning state
  const [currentPhase, setCurrentPhase] = useLiveScanState("currentPhase", 0);
  const [currentLine, setCurrentLine] = useLiveScanState("currentLine", 0);
  const [codeLines, setCodeLines] = useLiveScanState<CodeLine[]>("codeLines", []);
  const [stats, setStats] = useLiveScanState("stats", {
    linesScanned: 0,
    totalLines: 0,
    vulnerabilitiesFound: 0,
    elapsedTime: 0,
  });
  
  // Abort ref for stopping scan
  const scanAbortRef = useRef(false);
  const scanAbortControllerRef = useRef<AbortController | null>(null);
  const globalScanActivityIdRef = useRef<string | null>(null);
  const sourceLineCountsRef = useRef<Record<string, number>>({});
  const scanStartedAtRef = useRef<number | null>(null);
  const scanOutputRef = useRef<HTMLDivElement | null>(null);
  const correctionTimersRef = useRef<number[]>([]);

  // New scan result state
  const [scanResult, setScanResult] = useLiveScanState<ScanResult | null>("scanResult", null);
  const [selectedVulnerability, setSelectedVulnerability] = useState<VulnerabilityDetail | null>(null);
  const [branchFiles, setBranchFiles] = useState<string[]>([]);
  const [scanError, setScanError] = useLiveScanState<string>("scanError", "");
  const [thinkingSteps, setThinkingSteps] = useLiveScanState<string[]>("thinkingSteps", []);
  const [streamingChunks, setStreamingChunks] = useLiveScanState<ChunkOutput[]>("streamingChunks", []);
  const displayedChunks = streamingChunks.length ? streamingChunks : scanResult?.chunk_outputs ?? [];
  const openChunkItems = displayedChunks.map((chunk) => `${chunk.file_path}-${chunk.chunk_index}`);

  // Panel visibility state
  const [showPanel, setShowPanel] = useState(true);

  // Auto-select first scannable team when switching to team mode
  useEffect(() => {
    if (scanMode === "team" && allTeams.length > 0 && !selectedTeamId) {
      const adminTeam = allTeams.find((t) => t.current_user_role === "admin");
      const devTeam = allTeams.find((t) => t.current_user_role === "developer");
      setSelectedTeamId((adminTeam || devTeam || allTeams[0]).id);
    }
  }, [scanMode, allTeams]);

  // ── Detected language from first uploaded file ───────────────────────────
  // "C" | "C++" | null — null means no files yet
  const detectedProjectLanguage: "C" | "C++" | null =
    uploadedFiles.length === 0
      ? null
      : (() => {
          const firstSource = uploadedFiles.find((file) => {
            const ext = file.name.split(".").pop()?.toLowerCase() ?? "";
            return ext !== "zip";
          });
          const ext = firstSource?.name.split(".").pop()?.toLowerCase() ?? "";
          if (ext === "c" || ext === "h") return "C";
          if (["cpp", "cc", "cxx", "hpp", "hxx"].includes(ext)) return "C++";
          return null;
        })();

  // ── Effective language for upload gating ─────────────────────────────────
  // If a real project is selected and it has a stored language, that is the
  // authoritative constraint — regardless of what has been uploaded so far.
  // This prevents uploading .cpp files into a C project and vice-versa.
  // Falls back to detectedProjectLanguage when no project is selected.
  const effectiveLanguage: "C" | "C++" | null =
    selectedProject?.language === "C"   ? "C"   :
    selectedProject?.language === "C++" ? "C++" :
    detectedProjectLanguage;

  // Accepted extensions for the file input — driven by effectiveLanguage
  const acceptedExtensions =
    effectiveLanguage === "C"
      ? ".c,.h"
      : effectiveLanguage === "C++"
      ? ".cpp,.cxx,.cc,.hpp,.hxx,.h"
      : ".c,.h,.cpp,.cxx,.cc,.hpp,.hxx,.h,.zip";

  /** Returns true if a file is compatible with the effective project language */
  const isCompatibleFile = (file: File): boolean => {
    if (!effectiveLanguage) return true; // no constraint yet
    const ext = "." + (file.name.split(".").pop()?.toLowerCase() ?? "");
    if (ext === ".zip") return true;
    if (effectiveLanguage === "C") return [".c", ".h"].includes(ext);
    if (effectiveLanguage === "C++")
      return [".cpp", ".cxx", ".cc", ".hpp", ".hxx", ".h"].includes(ext);
    return true;
  };

  /** Badge label + colour for a given filename */
  const getFileLangBadge = (filename: string): { label: string; className: string } | null => {
    const ext = "." + (filename.split(".").pop()?.toLowerCase() ?? "");
    if ([".c", ".h"].includes(ext))
      return { label: "C", className: "bg-purple-500/20 text-purple-400 border-purple-500/30" };
    if ([".cpp", ".cxx", ".cc", ".hpp", ".hxx"].includes(ext))
      return { label: "C++", className: "bg-pink-500/20 text-pink-400 border-pink-500/30" };
    return null;
  };

  // Scan language string for CodeViewer / mock code ("c" | "cpp")
  const scanLang = effectiveLanguage === "C++" ? "cpp" : "c";

  const addLog = useCallback((message: string, type: ThinkingEventType = "info") => {
    const elapsedSeconds = scanStartedAtRef.current
      ? (Date.now() - scanStartedAtRef.current) / 1000
      : 0;
    const timestamp = formatElapsedClock(elapsedSeconds);
    const prefix = type === "error" ? "Error" : type === "warning" ? "Warning" : type === "success" ? "Done" : "Working";
    setThinkingSteps((prev) => [...prev, `[${timestamp}] ${prefix}: ${message}`]);
  }, []);

  const notifyScanFinished = useCallback((projectLabel: string, result: ScanResult) => {
    const preferences = getNotificationPreferences();
    if (preferences.scanCompleted) {
      toast.success("Scan completed", {
        description: `${projectLabel} finished with ${result.total_vulnerabilities} issue${result.total_vulnerabilities === 1 ? "" : "s"}.`,
      });
      addLocalNotification({
        title: "Scan completed",
        description: `${projectLabel} finished`,
        type: result.total_vulnerabilities > 0 ? "warning" : "success",
      });
    }
    if (preferences.criticalAlerts) {
      const criticalCount = result.vulnerabilities.filter((vulnerability) =>
        String(vulnerability.severity || "").toLowerCase() === "critical"
      ).length;
      if (criticalCount > 0) {
        toast.error("Critical vulnerability found", {
          description: `${criticalCount} critical issue${criticalCount === 1 ? "" : "s"} in ${projectLabel}.`,
        });
        addLocalNotification({
          title: "Critical vulnerability found",
          description: `${criticalCount} critical issue${criticalCount === 1 ? "" : "s"} in ${projectLabel}`,
          type: "critical",
        });
      }
    }
    if (scanMode === "team" && preferences.teamMemberScanned) {
      const memberName = currentUser?.user_metadata?.full_name || currentUser?.email || "A team member";
      toast.info("Team scan finished", {
        description: `${memberName} finished scan for ${projectLabel}.`,
      });
      addLocalNotification({
        title: "Team scan finished",
        description: `${memberName} finished scan for ${projectLabel}`,
        type: "info",
      });
    }
  }, [currentUser?.email, currentUser?.user_metadata?.full_name, scanMode]);

  const upsertStreamingChunk = useCallback((incoming: ChunkOutput) => {
    setStreamingChunks((prev) => {
      const key = `${incoming.file_path ?? ""}-${incoming.chunk_index}`;
      const existingIndex = prev.findIndex((chunk) => `${chunk.file_path ?? ""}-${chunk.chunk_index}` === key);
      if (existingIndex === -1) return [...prev, incoming];
      const next = [...prev];
      next[existingIndex] = { ...next[existingIndex], ...incoming };
      return next;
    });
  }, []);

  const replaceStreamingChunksForFile = useCallback((filePath: string, incomingChunks: ChunkOutput[]) => {
    setStreamingChunks((prev) => [
      ...prev.filter((chunk) => (chunk.file_path ?? "") !== filePath),
      ...incomingChunks,
    ]);
  }, []);

  const clearCorrectionTimers = useCallback(() => {
    correctionTimersRef.current.forEach((timer) => window.clearTimeout(timer));
    correctionTimersRef.current = [];
  }, []);

  const updateCorrectedChunk = useCallback((filePath: string, chunkIndex: number, correctedCode: string) => {
    setStreamingChunks((prev) => prev.map((chunk) =>
      (chunk.file_path === filePath && chunk.chunk_index === chunkIndex)
        ? { ...chunk, corrected_code: correctedCode }
        : chunk
    ));
    setScanResult((prev) => prev ? {
      ...prev,
      chunk_outputs: (prev.chunk_outputs ?? []).map((chunk) =>
        (chunk.file_path === filePath && chunk.chunk_index === chunkIndex)
          ? { ...chunk, corrected_code: correctedCode }
          : chunk
      ),
    } : prev);
  }, []);

  useEffect(() => () => clearCorrectionTimers(), [clearCorrectionTimers]);

  const sanitizeScanResultChunkRanges = useCallback((result: ScanResult): ScanResult => {
    const chunkOutputs = result.chunk_outputs ?? [];
    const invalidFiles = new Set<string>();
    const chunksByFile = chunkOutputs.reduce<Record<string, ChunkOutput[]>>((groups, chunk) => {
      const filePath = chunk.file_path ?? "";
      groups[filePath] = [...(groups[filePath] ?? []), chunk];
      return groups;
    }, {});

    Object.entries(chunksByFile).forEach(([filePath, chunks]) => {
      const knownSourceLines =
        sourceLineCountsRef.current[filePath]
        ?? Math.max(0, ...chunks.map((chunk) => Number(chunk.source_line_count) || 0));
      const maxChunkEnd = Math.max(0, ...chunks.map((chunk) => Number(chunk.end_line) || 0));
      if (knownSourceLines > 0 && maxChunkEnd > knownSourceLines) {
        invalidFiles.add(filePath);
      }
    });

    if (invalidFiles.size === 0) return result;
    addLog(`Ignored stale chunk data for ${Array.from(invalidFiles).join(", ")}`, "warning");
    const sanitizedChunks = chunkOutputs.filter((chunk) => !invalidFiles.has(chunk.file_path ?? ""));
    return {
      ...result,
      total_chunks_scanned: sanitizedChunks.length,
      chunk_outputs: sanitizedChunks,
      files: result.files.map((file) => ({
        ...file,
        chunk_outputs: (file.chunk_outputs ?? []).filter((chunk) => !invalidFiles.has(chunk.file_path ?? file.filename)),
      })),
    };
  }, [addLog]);

  const handleScanStreamEvent = useCallback((event: ScanStreamEvent) => {
    switch (event.event) {
      case "scan_started":
        addLog(`Streaming scan started for ${event.total_files} file${event.total_files === 1 ? "" : "s"}`, "info");
        if (event.scan_id) {
          updateGlobalScanActivity(globalScanActivityIdRef.current, { scanId: event.scan_id });
        }
        break;
      case "file_started":
        addLog(`Preparing ${event.file_path}`, "info");
        break;
      case "node":
        addLog(event.message, "info");
        break;
      case "chunks_ready":
        {
          const knownSourceLines = event.source_lines ?? sourceLineCountsRef.current[event.file_path] ?? 0;
          const maxChunkEnd = Math.max(0, ...event.chunks.map((chunk) => Number(chunk.end_line) || 0));
          if (knownSourceLines > 0 && maxChunkEnd > knownSourceLines) {
            addLog(
              `Ignored stale chunk stream for ${event.file_path}: chunk line ${maxChunkEnd} exceeds source line count ${knownSourceLines}`,
              "warning"
            );
            break;
          }
          const chunks = event.chunks.map((chunk) => ({
            ...chunk,
            file_path: chunk.file_path ?? event.file_path,
            source_line_count: (chunk.source_line_count ?? knownSourceLines) || undefined,
            chunker_version: chunk.chunker_version ?? event.chunker_version,
          }));
          addLog(
            `${event.total_chunks} semantic chunk${event.total_chunks === 1 ? "" : "s"} ready for ${event.file_path}${event.chunker_version ? ` (${event.chunker_version})` : ""}`,
            "success"
          );
          replaceStreamingChunksForFile(event.file_path, chunks);
          setScanResult((prev) => {
            const previousChunks = prev?.chunk_outputs ?? [];
            const keptChunks = previousChunks.filter((chunk) => (chunk.file_path ?? "") !== event.file_path);
            return {
              status: "streaming",
              total_vulnerabilities: prev?.total_vulnerabilities ?? 0,
              overall_risk_level: prev?.overall_risk_level ?? "Scanning",
              overall_risk_score: prev?.overall_risk_score ?? 0,
              files_analyzed: prev?.files_analyzed ?? 0,
              total_chunks_scanned: keptChunks.length + chunks.length,
              files_summary: prev?.files_summary ?? [],
              vulnerabilities: prev?.vulnerabilities ?? [],
              corrected_code: prev?.corrected_code ?? "Pending...",
              files: prev?.files ?? [],
              chunk_outputs: [...keptChunks, ...chunks],
              scan_id: prev?.scan_id ?? null,
            };
          });
        }
        break;
      case "chunk_started":
        addLog(event.message, "info");
        break;
      case "model_delta":
        setStreamingChunks((prev) => prev.map((chunk) =>
          chunk.file_path === event.file_path && chunk.chunk_index === event.chunk_index
            ? { ...chunk, model_output: `${chunk.model_output ?? ""}${event.text}`, analysis_complete: false }
            : chunk
        ));
        setScanResult((prev) => prev ? {
          ...prev,
          chunk_outputs: (prev.chunk_outputs ?? []).map((chunk) =>
            chunk.file_path === event.file_path && chunk.chunk_index === event.chunk_index
              ? { ...chunk, model_output: `${chunk.model_output ?? ""}${event.text}`, analysis_complete: false }
              : chunk
          ),
        } : prev);
        break;
      case "chunk_result":
        upsertStreamingChunk({ ...event.chunk, analysis_complete: true });
        setScanResult((prev) => {
          const previousChunks = prev?.chunk_outputs ?? [];
          const key = `${event.chunk.file_path ?? ""}-${event.chunk.chunk_index}`;
          const filtered = previousChunks.filter((chunk) => `${chunk.file_path ?? ""}-${chunk.chunk_index}` !== key);
          const vulnerabilities = [...filtered, event.chunk].flatMap((chunk) => chunk.vulnerabilities ?? []);
          return {
            status: "streaming",
            total_vulnerabilities: vulnerabilities.length,
            overall_risk_level: "Scanning",
            overall_risk_score: prev?.overall_risk_score ?? 0,
            files_analyzed: prev?.files_analyzed ?? 0,
            total_chunks_scanned: filtered.length + 1,
            files_summary: prev?.files_summary ?? [],
            vulnerabilities,
            corrected_code: prev?.corrected_code ?? "Pending...",
            files: prev?.files ?? [],
            chunk_outputs: [...filtered, event.chunk],
            scan_id: prev?.scan_id ?? null,
          };
        });
        addLog(`${event.chunk.file_path ?? event.file_path}: chunk ${event.chunk.chunk_index} streamed with ${event.chunk.vulnerabilities.length} issue${event.chunk.vulnerabilities.length === 1 ? "" : "s"}`, event.chunk.vulnerabilities.length ? "warning" : "success");
        break;
      case "correction_started":
        addLog(event.message, "info");
        break;
      case "correction_delta":
        updateCorrectedChunk(event.file_path, event.chunk_index, event.corrected_code);
        break;
      case "correction_result":
        updateCorrectedChunk(event.file_path, event.chunk_index, event.corrected_code);
        addLog(`Corrected code streamed for ${event.file_path}: chunk ${event.chunk_index}`, "success");
        break;
      case "scan_result":
        {
          const sanitizedResult = sanitizeScanResultChunkRanges(event.result);
          setScanResult(sanitizedResult);
          const finalChunks = sanitizedResult.chunk_outputs ?? [];
          if (finalChunks.length > 0) {
            setStreamingChunks(finalChunks);
          }
        }
        addLog("Final report assembled", "success");
        break;
      case "error":
        addLog(event.message, "error");
        break;
    }
  }, [addLog, replaceStreamingChunksForFile, sanitizeScanResultChunkRanges, updateCorrectedChunk, upsertStreamingChunk]);

  useEffect(() => {
    if (!isScanning && displayedChunks.length === 0) return;
    scanOutputRef.current?.scrollTo({
      top: scanOutputRef.current.scrollHeight,
      behavior: "smooth",
    });
  }, [displayedChunks.length, thinkingSteps.length, isScanning]);

  const renderThinkingStream = (emptyText: string) => {
    const activeIndex = thinkingSteps.length - 1;

    return (
      <div className="space-y-3">
        {thinkingSteps.length === 0 ? (
          <p className="text-sm text-muted-foreground">{emptyText}</p>
        ) : (
          thinkingSteps.map((step, index) => {
            const parsed = parseThinkingStep(step);
            const style = getThinkingStyle(parsed.message, parsed.type);
            const Icon = style.icon;
            const isActive = isScanning && index === activeIndex;
            return (
              <div
                key={`${step}-${index}`}
                className={cn(
                  "group rounded-md border p-3 transition-all duration-300 animate-slide-up",
                  style.className,
                  isActive && "shadow-[0_0_24px_rgba(16,185,129,0.14)]"
                )}
              >
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className={cn("relative grid h-7 w-7 place-items-center rounded-full bg-background/50", isActive && "animate-pulse")}>
                      <Icon className="h-3.5 w-3.5" />
                      {isActive && (
                        <span className={cn("absolute -right-0.5 -top-0.5 h-2 w-2 rounded-full animate-ping", style.dotClassName)} />
                      )}
                    </span>
                    <span className="text-[11px] font-semibold uppercase tracking-wide">{style.label}</span>
                  </div>
                  {parsed.time && (
                    <span className="rounded bg-background/60 px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">
                      {parsed.time}
                    </span>
                  )}
                </div>
                <p className="mt-2 text-sm font-medium text-foreground">{parsed.message}</p>
                {isActive && (
                  <div className="mt-2 flex items-center gap-1 text-xs text-muted-foreground">
                    <span className="h-1.5 w-1.5 rounded-full bg-current animate-bounce" />
                    <span className="h-1.5 w-1.5 rounded-full bg-current animate-bounce [animation-delay:120ms]" />
                    <span className="h-1.5 w-1.5 rounded-full bg-current animate-bounce [animation-delay:240ms]" />
                    <span className="ml-1">streaming</span>
                    <span className="ml-auto h-4 w-1.5 animate-pulse rounded-sm bg-current" />
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    );
  };

  const handleStopScan = () => {
    scanAbortRef.current = true;
    scanAbortControllerRef.current?.abort();
    scanAbortControllerRef.current = null;
    clearCorrectionTimers();
    setIsScanning(false);
    failGlobalScanActivity(globalScanActivityIdRef.current, "Scan cancelled by user.");
    addLog("Scan cancelled by user", "warning");
  };

  useEffect(() => {
    const resume = () => setShowLiveScan(true);
    const cancel = () => handleStopScan();
    window.addEventListener("secureguard:resume-scan-view", resume);
    window.addEventListener("secureguard:cancel-active-scan", cancel);
    return () => {
      window.removeEventListener("secureguard:resume-scan-view", resume);
      window.removeEventListener("secureguard:cancel-active-scan", cancel);
    };
  });

  useEffect(() => {
    if (searchParams.get("resumeScan") === "1") {
      setShowLiveScan(true);
    }
  }, [searchParams, setShowLiveScan]);

  const handleStartScan = async () => {
    const isAutoRescan = searchParams.get("autoStart") === "1";
    let globalScanActivityId: string | null = null;
    clearLiveScanState();
    scanAbortRef.current = false;
    scanAbortControllerRef.current = new AbortController();
    scanStartedAtRef.current = Date.now();
    clearCorrectionTimers();
    setAutoRescanPreparing(isAutoRescan);
    setIsScanning(true);
    setScanComplete(false);
    setShowLiveScan(true);
    setScanResult(null);
    setScanError("");
    setStreamingChunks([]);
    setCurrentPhase(0);
    setCurrentLine(0);
    setThinkingSteps(["Preparing source files", "Building semantic chunks", "Waiting for chunk analysis"]);

    // Resolve project id/name — create new project if needed
    let resolvedProjectId = selectedProjectId;
    let resolvedProjectName = selectedProjectName || projectName;
    let createdProjectDuringScan = false;

    if (!resolvedProjectId && !resolvedProjectName.trim()) {
      toast.error("Project is required", { description: "Select an existing project or enter a new project name before starting analysis." });
      setIsScanning(false);
      return;
    }

    if (selectedProjectId === "__new__") {
      const trimmedName = newProjectName.trim();
      if (!/^[a-zA-Z]/.test(trimmedName)) {
        toast.error("Invalid Project Name", { description: "Project name must start with a letter." });
        setIsScanning(false);
        return;
      }
      try {
        const created = await createProject({
          name: trimmedName,
          type: scanMode,
          language: activeTab === "github"
            ? (isTeamMode ? selectedTeamGithubLanguage ?? undefined : selectedGithubLanguage ?? undefined)
            : detectedProjectLanguage ?? undefined,
          upload_type: activeTab === "github" ? "github" : "upload",
          github_repo: activeTab === "github" ? (isTeamMode ? selectedApiTeam?.github_repo ?? undefined : selectedGithubRepo?.url) : undefined,
          team_id: scanMode === "team" ? selectedTeamId : undefined,
        });
        resolvedProjectId = created.id;
        resolvedProjectName = created.name;
        createdProjectDuringScan = true;
        if (getNotificationPreferences().newProject) {
          toast.info("New project added", { description: `${created.name} was created.` });
          addLocalNotification({
            title: "New project added",
            description: `${created.name} was created`,
            type: "info",
          });
        }
        await refetchProjects();
      } catch (err: any) {
        setScanError(err.message || "Failed to create project");
        setIsScanning(false);
        return;
      }
    }

    const firstFile = uploadedFiles[0];

    // ── UPLOAD MODE ──────────────────────────────────────────────────────────
    if (activeTab === "upload") {
      type FileTuple = { name: string; content: string };
      const filesToScan: FileTuple[] = [];

      if (isAutoRescan && resolvedProjectId && resolvedProjectId !== "__new__") {
        setAutoRescanPreparing(true);
        try {
          const selectedIds = selectedFileIds.size > 0 ? Array.from(selectedFileIds) : undefined;
          const sourceFiles = await listProjectSourceFiles(resolvedProjectId, selectedIds);
          for (const sourceFile of sourceFiles) {
            filesToScan.push({ name: sourceFile.name, content: sourceFile.content });
          }
        } finally {
          setAutoRescanPreparing(false);
        }
      } else if (projectFiles.length > 0 && selectedFileIds.size > 0) {
        try {
          const sourceFiles = await listProjectSourceFiles(resolvedProjectId, Array.from(selectedFileIds));
          for (const sourceFile of sourceFiles) {
            filesToScan.push({ name: sourceFile.name, content: sourceFile.content });
          }
        } catch (err: any) {
          addLog(`Warning: could not read selected project files - ${err.message || "unknown error"}`, "warning");
        }
      }

      for (const file of uploadedFiles) {
        if (file.name.toLowerCase().endsWith(".zip")) continue;
        const text = await file.text();
        filesToScan.push({ name: file.name, content: text });
      }

      if (filesToScan.length === 0 && uploadedFiles.length === 0) {
        setScanError("Select at least one C/C++ file or ZIP archive to scan.");
        setIsScanning(false);
        return;
      }

      // Use the first file for the code viewer animation
      const primaryFile = filesToScan[0];
      const code = primaryFile?.content ?? "";
      const lines = splitSourceLines(code);
      sourceLineCountsRef.current = filesToScan.reduce<Record<string, number>>((counts, file) => {
        counts[file.name] = splitSourceLines(file.content).length;
        return counts;
      }, {});

      const initialLines: CodeLine[] = lines.map((content, index) => ({
        lineNumber: index + 1,
        content,
        status: "pending" as const,
      }));
      setCodeLines(initialLines);
      setStats({ linesScanned: 0, totalLines: lines.length, vulnerabilitiesFound: 0, elapsedTime: 0 });

      addLog("Preparing source package...", "info");
      setCurrentPhase(1);
      addLog("Collecting static evidence...", "info");
      await new Promise(r => setTimeout(r, 600));
      setCurrentPhase(2);
      const zipUploadCount = uploadedFiles.filter((file) => file.name.toLowerCase().endsWith(".zip")).length;
      const pendingUploadCount = filesToScan.length + zipUploadCount;
      globalScanActivityId = startGlobalScanActivity({
        title: resolvedProjectName || primaryFile?.name || "Security scan",
        detail: `Scanning ${pendingUploadCount} source item${pendingUploadCount === 1 ? "" : "s"}. You can keep working while the report is prepared.`,
      });
      globalScanActivityIdRef.current = globalScanActivityId;
      addLog(
        zipUploadCount > 0
          ? `Reviewing ${pendingUploadCount} upload${pendingUploadCount === 1 ? "" : "s"}; ZIP archives will be filtered on the backend.`
          : `Reviewing ${filesToScan.length} file${filesToScan.length === 1 ? "" : "s"} for vulnerabilities...`,
        "info"
      );

      const startTime = Date.now();
      const timerInterval = setInterval(() => {
        setStats(prev => ({ ...prev, elapsedTime: Math.floor((Date.now() - startTime) / 1000) }));
      }, 1000);

      // Animate lines while waiting for real API response
      let animIndex = 0;
      const lineAnimInterval = setInterval(() => {
        if (animIndex < lines.length) {
          setCurrentLine(animIndex + 1);
          setCodeLines(prev => prev.map((line, idx) => {
            if (idx === animIndex) return { ...line, status: "scanning" };
            if (idx < animIndex) return { ...line, status: "safe" };
            return line;
          }));
          setStats(prev => ({ ...prev, linesScanned: animIndex + 1 }));
          animIndex++;
        }
      }, 80);

      try {
        let combinedResult: ScanResult | null = null;

        if (uploadedFiles.length > 0) {
          combinedResult = await triggerUploadedFileScanStream(
            uploadedFiles,
            {
              project_id: resolvedProjectId ?? "",
              project_name: resolvedProjectName ?? "",
            },
            handleScanStreamEvent,
            scanAbortControllerRef.current.signal
          );
        } else {
          const rescanFiles = filesToScan.map(
            (fileTuple) => new File([fileTuple.content], fileTuple.name, { type: "text/plain" })
          );
          combinedResult = await triggerUploadedFileScanStream(
            rescanFiles,
            {
              project_id: resolvedProjectId ?? "",
              project_name: resolvedProjectName ?? "",
            },
            handleScanStreamEvent,
            scanAbortControllerRef.current.signal
          );
        }

        clearInterval(lineAnimInterval);
        clearInterval(timerInterval);

        if (!combinedResult) throw new Error("No scan results returned");
        combinedResult = sanitizeScanResultChunkRanges(combinedResult);

        // Mark vulnerable lines on the code viewer (primary file only)
        setCodeLines(prev => prev.map((line) => {
          const vuln = combinedResult!.vulnerabilities.find(v => v.absolute_line === line.lineNumber);
          return { ...line, status: vuln ? "vulnerable" : "safe", vulnerability: vuln?.cwe_name };
        }));

        setStats(prev => ({
          ...prev,
          linesScanned: lines.length,
          vulnerabilitiesFound: combinedResult!.total_vulnerabilities,
          elapsedTime: Math.floor((Date.now() - startTime) / 1000),
        }));

        setScanResult(combinedResult);
        setThinkingSteps([
          ...(combinedResult.chunk_outputs ?? []).map(
            (chunk) =>
              `Chunk ${chunk.chunk_index}: ${chunk.chunk_name} lines ${chunk.start_line}-${chunk.end_line} reviewed with ${chunk.vulnerabilities.length} issue${chunk.vulnerabilities.length === 1 ? "" : "s"}.`
          ),
          "Report assembled",
        ]);
        setSelectedVulnerability(combinedResult.vulnerabilities[0] ?? null);
        setCurrentPhase(3);
        setCurrentPhase(4);
        addLog("Assembling report...", "info");
        await new Promise(r => setTimeout(r, 500));
        setCurrentPhase(5);
        notifyScanFinished(resolvedProjectName || primaryFile?.name || "Security scan", combinedResult);
        completeGlobalScanActivity(globalScanActivityId, {
          scanId: combinedResult.scan_id,
          issueCount: combinedResult.total_vulnerabilities,
          riskLevel: combinedResult.overall_risk_level,
          title: resolvedProjectName || primaryFile?.name || "Security scan",
        });
        addLog(`Found ${combinedResult.total_vulnerabilities} vulnerabilities — Risk: ${combinedResult.overall_risk_level}`, combinedResult.total_vulnerabilities > 0 ? "warning" : "success");
        addLog("Scan complete!", "success");

      } catch (err: any) {
        clearInterval(lineAnimInterval);
        clearInterval(timerInterval);
        if (createdProjectDuringScan && resolvedProjectId && err.message?.includes("syntax error")) {
          await deleteProject(resolvedProjectId).catch(() => undefined);
          await refetchProjects();
        }
        const message = friendlyScanError(err.message || "Scan failed");
        setScanError(message);
        setCurrentPhase(5);
        failGlobalScanActivity(globalScanActivityId, message);
        addLog(`Error: ${message}`, "warning");
      }

      setScanComplete(true);
      setIsScanning(false);
      return;
    }

    // ── GITHUB MODE — personal project with directly-connected repo ─────────
    if (activeTab === "github" && !isTeamMode) {
      const startTime = Date.now();
      const timerInterval = setInterval(() => {
        setStats(prev => ({ ...prev, elapsedTime: Math.floor((Date.now() - startTime) / 1000) }));
      }, 1000);

      setCodeLines([]);
      setStats({ linesScanned: 0, totalLines: 0, vulnerabilitiesFound: 0, elapsedTime: 0 });
      sourceLineCountsRef.current = {};
      let previewInterval: ReturnType<typeof setInterval> | null = null;

      try {
        if (!githubInstallationId || !selectedGithubRepo) {
          throw new Error("Connect GitHub and select a repository first.");
        }
        const files = Array.from(selectedGithubFiles);
        if (files.length === 0) {
          throw new Error("Select at least one C/C++ file or ZIP archive from GitHub.");
        }
        let previewLines = buildQueuedSourcePreview(files);
        const previewFile = files.find((filePath) => extensionOf(filePath) !== ".zip") ?? files[0];
        if (previewFile && extensionOf(previewFile) !== ".zip") {
          try {
            const content = await fetchPersonalGithubFileContent(
              githubInstallationId,
              selectedGithubRepo.full_name,
              branch,
              previewFile,
            );
            previewLines = codeLinesFromSource(`// ${previewFile}\n${content.content}`);
          } catch (err: any) {
            addLog(`Could not load live source preview for ${previewFile}; scanning will continue.`, "warning");
          }
        }
        setCodeLines(previewLines);
        setStats({ linesScanned: 0, totalLines: previewLines.length, vulnerabilitiesFound: 0, elapsedTime: 0 });
        let previewIndex = 0;
        previewInterval = setInterval(() => {
          setCurrentLine((previewIndex % previewLines.length) + 1);
          setCodeLines((prev) => prev.map((line, idx) => ({
            ...line,
            status: idx === previewIndex % previewLines.length ? "scanning" : idx < previewIndex ? "safe" : line.status,
          })));
          setStats((prev) => ({ ...prev, linesScanned: Math.min(previewIndex + 1, previewLines.length) }));
          previewIndex += 1;
        }, 160);
        globalScanActivityId = startGlobalScanActivity({
          title: resolvedProjectName || selectedGithubRepo.full_name || "GitHub scan",
          detail: `Fetching ${files.length} GitHub file${files.length === 1 ? "" : "s"} from ${branch}. You can keep working while analysis runs.`,
        });
        globalScanActivityIdRef.current = globalScanActivityId;
        addLog("Preparing source package...", "info");
        setCurrentPhase(1);

        addLog(`Fetching selected files from ${selectedGithubRepo.full_name}:${branch}...`, "info");
        setBranchFiles(files);
        updateGlobalScanActivity(globalScanActivityId, {
          detail: `Reviewing ${files.length} selected GitHub file${files.length === 1 ? "" : "s"} from ${branch}. The report will appear in Reports.`,
        });
        addLog(`Selected ${files.length} GitHub file${files.length === 1 ? "" : "s"}`, "success");

        setCurrentPhase(2);
        addLog("Reviewing files for vulnerabilities...", "info");
        addLog("This may take a moment depending on file count...", "info");

        const result = await triggerGithubScanStream(
          `/projects/${resolvedProjectId}/scans/stream`,
          {
            branch,
            selected_files: files,
            project_id: resolvedProjectId ?? "",
            project_name: resolvedProjectName ?? "",
            installation_id: githubInstallationId,
            repo_full_name: selectedGithubRepo.full_name,
          },
          handleScanStreamEvent,
          scanAbortControllerRef.current?.signal,
        );

        clearInterval(timerInterval);
        if (previewInterval) clearInterval(previewInterval);

        setStats({
          linesScanned: previewLines.length,
          totalLines: previewLines.length,
          vulnerabilitiesFound: result.total_vulnerabilities,
          elapsedTime: Math.floor((Date.now() - startTime) / 1000),
        });
        setCodeLines((prev) => prev.map((line) => ({ ...line, status: "safe" })));

        setScanResult(result);
        setThinkingSteps([
          ...(result.chunk_outputs ?? []).map(
            (chunk) =>
              `Chunk ${chunk.chunk_index}: ${chunk.chunk_name} lines ${chunk.start_line}-${chunk.end_line} reviewed with ${chunk.vulnerabilities.length} issue${chunk.vulnerabilities.length === 1 ? "" : "s"}.`
          ),
          "Report assembled",
        ]);
        setCurrentPhase(3);
        setCurrentPhase(4);
        addLog("Assembling report...", "info");
        await new Promise(r => setTimeout(r, 500));
        setCurrentPhase(5);
        notifyScanFinished(resolvedProjectName || selectedGithubRepo.full_name || "Security scan", result);
        completeGlobalScanActivity(globalScanActivityId, {
          scanId: result.scan_id,
          issueCount: result.total_vulnerabilities,
          riskLevel: result.overall_risk_level,
          title: resolvedProjectName || selectedGithubRepo.full_name || "GitHub scan",
        });
        addLog(`Found ${result.total_vulnerabilities} vulnerabilities — Risk: ${result.overall_risk_level}`, result.total_vulnerabilities > 0 ? "warning" : "success");
        addLog("Scan complete!", "success");

      } catch (err: any) {
        clearInterval(timerInterval);
        if (previewInterval) clearInterval(previewInterval);
        if (createdProjectDuringScan && resolvedProjectId && err.message?.includes("syntax error")) {
          await deleteProject(resolvedProjectId).catch(() => undefined);
          await refetchProjects();
        }
        const message = err?.name === "AbortError"
          ? "Scan cancelled by user."
          : friendlyScanError(err.message || "Scan failed");
        setScanError(message);
        setCurrentPhase(5);
        failGlobalScanActivity(globalScanActivityId, message);
        addLog(`Error: ${message}`, "warning");
      }

      setScanComplete(true);
      setIsScanning(false);
      scanAbortControllerRef.current = null;
      return;
    }

    // ── GITHUB MODE — team project ───────────────────────────────────────────
    // Team mode uses the selected team directly; personal mode uses the
    // project's team if it has one.
    const effectiveTeamId = isTeamMode ? selectedTeamId : "";

    if (activeTab === "github" && effectiveTeamId) {
      const startTime = Date.now();
      const timerInterval = setInterval(() => {
        setStats(prev => ({ ...prev, elapsedTime: Math.floor((Date.now() - startTime) / 1000) }));
      }, 1000);

      setCodeLines([]);
      setStats({ linesScanned: 0, totalLines: 0, vulnerabilitiesFound: 0, elapsedTime: 0 });
      sourceLineCountsRef.current = {};
      let previewInterval: ReturnType<typeof setInterval> | null = null;

      try {
        globalScanActivityId = startGlobalScanActivity({
          title: resolvedProjectName || selectedApiTeam?.name || "Team scan",
          detail: `Fetching team source files from ${branch}. You can move around SecureGuard while analysis continues.`,
        });
        addLog("Preparing source package...", "info");
        setCurrentPhase(1);

        const files = Array.from(selectedTeamGithubFiles);
        if (files.length === 0) {
          throw new Error("Select at least one team GitHub file to scan.");
        }
        let previewLines = buildQueuedSourcePreview(files);
        const previewFile = files.find((filePath) => extensionOf(filePath) !== ".zip") ?? files[0];
        if (previewFile && extensionOf(previewFile) !== ".zip") {
          try {
            const content = await fetchTeamFileContent(effectiveTeamId, branch, previewFile);
            previewLines = codeLinesFromSource(`// ${previewFile}\n${content.content}`);
          } catch (err: any) {
            addLog(`Could not load live source preview for ${previewFile}; scanning will continue.`, "warning");
          }
        }
        setCodeLines(previewLines);
        setStats({ linesScanned: 0, totalLines: previewLines.length, vulnerabilitiesFound: 0, elapsedTime: 0 });
        let previewIndex = 0;
        previewInterval = setInterval(() => {
          setCurrentLine((previewIndex % previewLines.length) + 1);
          setCodeLines((prev) => prev.map((line, idx) => ({
            ...line,
            status: idx === previewIndex % previewLines.length ? "scanning" : idx < previewIndex ? "safe" : line.status,
          })));
          setStats((prev) => ({ ...prev, linesScanned: Math.min(previewIndex + 1, previewLines.length) }));
          previewIndex += 1;
        }, 160);

        addLog(`Preparing ${files.length} selected team file${files.length === 1 ? "" : "s"} from branch: ${branch}...`, "info");
        setBranchFiles(files);
        updateGlobalScanActivity(globalScanActivityId, {
          detail: `Reviewing ${files.length} team file${files.length === 1 ? "" : "s"} from ${branch}. The report will appear in Reports.`,
        });
        addLog(`Selected ${files.length} team GitHub file${files.length === 1 ? "" : "s"}`, "success");

        setCurrentPhase(2);
        addLog("Reviewing files for vulnerabilities...", "info");
        addLog("This may take a moment depending on file count...", "info");

        const result = await triggerGithubScanStream(
          `/teams/${effectiveTeamId}/scans/stream`,
          {
            branch,
            selected_files: files,
            project_id: resolvedProjectId ?? "",
            project_name: resolvedProjectName ?? "",
          },
          handleScanStreamEvent,
          scanAbortControllerRef.current?.signal,
        );

        clearInterval(timerInterval);
        if (previewInterval) clearInterval(previewInterval);

        setStats({
          linesScanned: previewLines.length,
          totalLines: previewLines.length,
          vulnerabilitiesFound: result.total_vulnerabilities,
          elapsedTime: Math.floor((Date.now() - startTime) / 1000),
        });
        globalScanActivityIdRef.current = globalScanActivityId;
        setCodeLines((prev) => prev.map((line) => ({ ...line, status: "safe" })));

        setScanResult(result);
        setThinkingSteps([
          ...(result.chunk_outputs ?? []).map(
            (chunk) =>
              `Chunk ${chunk.chunk_index}: ${chunk.chunk_name} lines ${chunk.start_line}-${chunk.end_line} reviewed with ${chunk.vulnerabilities.length} issue${chunk.vulnerabilities.length === 1 ? "" : "s"}.`
          ),
          "Report assembled",
        ]);
        setCurrentPhase(3);
        setCurrentPhase(4);
        addLog("Assembling report...", "info");
        await new Promise(r => setTimeout(r, 500));
        setCurrentPhase(5);
        notifyScanFinished(resolvedProjectName || selectedApiTeam?.name || "Team scan", result);
        completeGlobalScanActivity(globalScanActivityId, {
          scanId: result.scan_id,
          issueCount: result.total_vulnerabilities,
          riskLevel: result.overall_risk_level,
          title: resolvedProjectName || selectedApiTeam?.name || "Team scan",
        });
        addLog(`Found ${result.total_vulnerabilities} vulnerabilities — Risk: ${result.overall_risk_level}`, result.total_vulnerabilities > 0 ? "warning" : "success");
        addLog("Scan complete!", "success");

      } catch (err: any) {
        clearInterval(timerInterval);
        if (previewInterval) clearInterval(previewInterval);
        if (createdProjectDuringScan && resolvedProjectId && err.message?.includes("syntax error")) {
          await deleteProject(resolvedProjectId).catch(() => undefined);
          await refetchProjects();
        }
        const message = friendlyScanError(err.message || "Scan failed");
        setScanError(message);
        setCurrentPhase(5);
        failGlobalScanActivity(globalScanActivityId, message);
        addLog(`Error: ${message}`, "warning");
      }

      setScanComplete(true);
      setIsScanning(false);
      return;
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(true);
  };

  const handleDragLeave = () => {
    setIsDragOver(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    const newFiles = Array.from(e.dataTransfer.files).filter((f) => {
      if (f.size > 10 * 1024 * 1024) {
        toast.error(`File too large: ${f.name}`, {
          description: "File size exceeds the 10 MB limit.",
        });
        return false;
      }
      if (projectFiles.some(pf => pf.name === f.name) || uploadedFiles.some(uf => uf.name === f.name)) {
        toast.error(`Duplicate file: ${f.name}`, {
          description: "A file with this name already exists in the project or upload list.",
        });
        return false;
      }
      if (!isCompatibleFile(f)) {
        toast.error(`Wrong file type: ${f.name}`, {
          description: `This project uses ${effectiveLanguage ?? detectedProjectLanguage}. Only ${acceptedExtensions} files are allowed.`,
        });
        return false;
      }
      return true;
    });
    if (newFiles.length > 0) {
      setUploadedFiles((prev) => [...prev, ...newFiles]);
      if (uploadedFiles.length === 0) {
        const reader = new FileReader();
        reader.onload = (ev) => setFileContent(ev.target?.result as string || "");
        reader.readAsText(newFiles[0]);
      }
    }
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const newFiles = Array.from(e.target.files || []).filter((f) => {
      if (f.size > 10 * 1024 * 1024) {
        toast.error(`File too large: ${f.name}`, {
          description: "File size exceeds the 10 MB limit.",
        });
        return false;
      }
      if (projectFiles.some(pf => pf.name === f.name) || uploadedFiles.some(uf => uf.name === f.name)) {
        toast.error(`Duplicate file: ${f.name}`, {
          description: "A file with this name already exists in the project or upload list.",
        });
        return false;
      }
      if (!isCompatibleFile(f)) {
        toast.error(`Wrong file type: ${f.name}`, {
          description: `This project uses ${effectiveLanguage ?? detectedProjectLanguage}. Only ${acceptedExtensions} files are allowed.`,
        });
        return false;
      }
      return true;
    });
    e.target.value = "";
    if (newFiles.length > 0) {
      setUploadedFiles((prev) => [...prev, ...newFiles]);
      if (uploadedFiles.length === 0) {
        const reader = new FileReader();
        reader.onload = (ev) => setFileContent(ev.target?.result as string || "");
        reader.readAsText(newFiles[0]);
      }
    }
  };

  const handleRemoveFile = (index: number) => {
    setUploadedFiles((prev) => {
      const next = prev.filter((_, i) => i !== index);
      if (next.length === 0) {
        setFileContent("");
      } else if (index === 0 && next.length > 0) {
        // Re-read first file
        const reader = new FileReader();
        reader.onload = (ev) => {
          setFileContent(ev.target?.result as string || "");
        };
        reader.readAsText(next[0]);
      }
      return next;
    });
  };

  const handleReset = () => {
    setIsScanning(false);
    setScanComplete(false);
    setCurrentPhase(0);
    setCurrentLine(0);
    setCodeLines([]);
    setUploadedFiles([]);
    setFileContent("");
    setProjectName("");
    setSelectedProjectId("");
    setSelectedProjectName("");
    setNewProjectName("");
    setIsCreatingProject(false);
    setScanResult(null);
    setBranchFiles([]);
    setScanError("");
    setThinkingSteps([]);
    setStreamingChunks([]);
    sourceLineCountsRef.current = {};
    scanStartedAtRef.current = null;
    setProjectFiles([]);
    setSelectedFileIds(new Set());
    setSaveToProject({});
    setSelectedGithubRepoName("");
    setGithubBranches([]);
    setGithubFiles([]);
    setGithubFileSearch("");
    setGithubFileFilter("all");
    setSelectedGithubFiles(new Set());
    setStats({
      linesScanned: 0,
      totalLines: 0,
      vulnerabilitiesFound: 0,
      elapsedTime: 0,
    });
    clearLiveScanState();
  };

  const githubReady = isTeamMode
    ? !!(selectedApiTeam?.github_repo && branch && selectedTeamGithubFiles.size > 0)
    : !!(githubInstallationId && selectedGithubRepo && branch && selectedGithubFiles.size > 0);

  // Resolve the effective project name for validation
  const effectiveProjectName = selectedProjectId === "__new__"
    ? newProjectName.trim()
    : (selectedProjectName || projectName).trim();

  // Team viewers cannot scan; in personal mode a project must be selected/named;
  // in team mode a team must be selected and the user must be admin/developer.
  // In personal upload mode: can scan if there are uploaded files OR selected project files.
  const hasFilesToScan =
    uploadedFiles.length > 0 || selectedFileIds.size > 0;

  const shouldShowUploadCard =
    uploadedFiles.length > 0 ||
    !selectedProjectId ||
    selectedProjectId === "__new__" ||
    (!projectFilesLoading && projectFiles.length === 0);

  const canStartScan =
    !isViewer &&
    (isTeamMode
      ? !!(selectedTeamId && canScanInTeam) && effectiveProjectName !== "" && (activeTab === "upload" ? uploadedFiles.length > 0 : githubReady)
      : activeTab === "github"
        ? effectiveProjectName !== "" && githubReady
        : effectiveProjectName !== "" && hasFilesToScan
    );

  const queuedFileCount = activeTab === "github"
    ? (isTeamMode ? selectedTeamGithubFiles.size : selectedGithubFiles.size)
    : branchFiles.length || uploadedFiles.length || selectedFileIds.size;
  const isUploadScan = activeTab === "upload";

  // Determine GitHub tab behavior based on selected project / team mode
  const renderGitHubTab = () => {
    if (!isTeamMode) {
      const selectedSourceCount = selectedGithubFiles.size;
      const allVisibleSourceSelected = githubSourceFiles.length > 0 && githubSourceFiles.every((file) => selectedGithubFiles.has(file.path));
      const githubSteps = [
        { number: "1", label: "Connect GitHub", active: !githubInstallationId, done: !!githubInstallationId },
        { number: "2", label: "Select Repository", active: !!githubInstallationId && !selectedGithubRepo, done: !!selectedGithubRepo },
        { number: "3", label: "Select Files", active: !!selectedGithubRepo, done: selectedSourceCount > 0 },
      ];

      return (
        <CardContent className="pt-6 space-y-6">
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <Github className="h-6 w-6" />
              <h3 className="text-xl font-semibold">Import from GitHub</h3>
            </div>
            <p className="text-sm text-muted-foreground">
              Connect your GitHub account, select a repository, and choose C/C++ files or ZIP archives to scan.
            </p>
          </div>

          <div className="border-t border-border/60 pt-5">
            <div className="flex items-center gap-4">
              {githubSteps.map((step, index) => (
                <Fragment key={step.number}>
                  <div className="flex shrink-0 items-center gap-3">
                    <span
                      className={cn(
                        "grid h-8 w-8 place-items-center rounded-full text-sm font-semibold",
                        step.done || step.active ? "bg-primary text-primary-foreground" : "bg-muted text-muted-foreground"
                      )}
                    >
                      {step.number}
                    </span>
                    <span className="text-sm font-medium">{step.label}</span>
                  </div>
                  {index < githubSteps.length - 1 && <span className="h-px flex-1 bg-border" />}
                </Fragment>
              ))}
            </div>
          </div>

          <div className="rounded-lg border border-border/50 bg-muted/15 p-5 text-center">
            <p className="mb-4 text-sm text-muted-foreground">
              {githubInstallationId ? "GitHub is connected. Refresh repositories if you changed app access." : "Connect your GitHub account to import repositories."}
            </p>
            <div className="flex flex-col items-center justify-center gap-3 sm:flex-row">
              <Button className="min-w-64 gap-2" onClick={handleConnectGithub}>
                <Github className="h-4 w-4" />
                {githubInstallationId ? "Reconnect GitHub" : "Connect GitHub"}
              </Button>
              {githubInstallationId && (
                <Button type="button" variant="outline" className="min-w-44 gap-2" onClick={handleDisconnectGithub}>
                  <Unplug className="h-4 w-4" />
                  Disconnect GitHub
                </Button>
              )}
            </div>
            <div className="mt-3 flex items-center justify-center gap-2 text-xs text-muted-foreground">
              <Lock className="h-3.5 w-3.5 text-amber-400" />
              We never store your GitHub credentials.
            </div>
          </div>

          <div className="rounded-lg border border-border/50 bg-muted/10 p-5">
            <div className="grid gap-4 md:grid-cols-[1fr_1fr]">
              <div className="space-y-2">
                <Label>Repository *</Label>
                <div className="flex gap-2">
                  <Select
                    value={selectedGithubRepoName}
                    onValueChange={setSelectedGithubRepoName}
                    disabled={!githubInstallationId || githubReposLoading}
                  >
                    <SelectTrigger>
                      <SelectValue placeholder={githubReposLoading ? "Loading repositories..." : "Select a repository"} />
                    </SelectTrigger>
                    <SelectContent>
                      {githubRepos.map((repo) => (
                        <SelectItem key={repo.full_name} value={repo.full_name}>
                          {repo.full_name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <Button
                    type="button"
                    variant="outline"
                    size="icon"
                    onClick={() => githubInstallationId && loadGithubRepos(githubInstallationId)}
                    disabled={!githubInstallationId || githubReposLoading}
                  >
                    <RefreshCw className={cn("h-4 w-4", githubReposLoading && "animate-spin")} />
                  </Button>
                </div>
                {githubReposError && <p className="text-xs text-destructive">{githubReposError}</p>}
              </div>

              <div className="space-y-2">
                <Label>Branch</Label>
                <Select value={branch} onValueChange={setBranch} disabled={!selectedGithubRepo || githubBranchesLoading}>
                  <SelectTrigger>
                    <SelectValue placeholder={githubBranchesLoading ? "Loading branches..." : "Select branch"} />
                  </SelectTrigger>
                  <SelectContent>
                    {githubBranches.map((branchName) => (
                      <SelectItem key={branchName} value={branchName}>
                        {branchName}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>

            {selectedGithubRepo && (
              <div className="mt-5 flex flex-wrap items-center justify-between gap-3">
                <div>
                  <div className="flex items-center gap-2">
                    <p className="font-semibold">{selectedGithubRepo.full_name.split("/")[1]}</p>
                    <Badge variant="outline">{selectedGithubRepo.private ? "Private" : "Public"}</Badge>
                  </div>
                  <a href={selectedGithubRepo.url} target="_blank" rel="noreferrer" className="text-sm text-muted-foreground hover:text-primary">
                    {selectedGithubRepo.url}
                  </a>
                </div>
                <div className="flex gap-2">
                  <Badge variant="secondary" className="gap-1"><GitFork className="h-3.5 w-3.5" />{branch}</Badge>
                  <Badge variant="secondary" className="gap-1"><Star className="h-3.5 w-3.5" />{selectedGithubRepo.stars ?? 0}</Badge>
                  <Badge variant="secondary" className="gap-1"><GitFork className="h-3.5 w-3.5" />{selectedGithubRepo.forks ?? 0}</Badge>
                </div>
              </div>
            )}
          </div>

          <div className="rounded-lg border border-border/50 bg-muted/10 p-5">
            <div className="mb-4 flex items-center justify-between gap-3">
              <div>
                <h4 className="font-medium">Select files to scan</h4>
                <p className="text-xs text-muted-foreground">C, C++, and ZIP archive files are selectable for analysis.</p>
              </div>
              {githubFilesLoading && <Loader2 className="h-4 w-4 animate-spin text-primary" />}
            </div>
            <div className="mb-4 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
              <div className="relative max-w-md flex-1">
                <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  value={githubFileSearch}
                  onChange={(event) => setGithubFileSearch(event.target.value)}
                  placeholder="Search files..."
                  className="pl-9"
                />
              </div>
              <Select value={githubFileFilter} onValueChange={(value: "all" | "source") => setGithubFileFilter(value)}>
                <SelectTrigger className="w-44">
                  <Filter className="mr-2 h-4 w-4" />
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">Filter: All Files</SelectItem>
                  <SelectItem value="source">Filter: C/C++ & ZIP</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {githubFilesError && <p className="mb-3 text-sm text-destructive">{githubFilesError}</p>}

            <div className="overflow-hidden rounded-md border border-border/60">
              <div className="grid grid-cols-[44px_1fr_120px] items-center bg-muted/30 px-3 py-2 text-xs font-medium text-muted-foreground">
                <Checkbox
                  checked={allVisibleSourceSelected}
                  onCheckedChange={(checked) => {
                    setSelectedGithubFiles(checked ? new Set(githubSourceFiles.map((file) => file.path)) : new Set());
                  }}
                  disabled={githubSourceFiles.length === 0}
                />
                <span>File Name</span>
                <span>Language</span>
              </div>
              <div className="max-h-72 overflow-auto">
                {filteredGithubFiles.length === 0 ? (
                  <div className="px-3 py-8 text-center text-sm text-muted-foreground">
                    {githubFilesLoading ? "Loading files..." : "No files found."}
                  </div>
                ) : (
                  filteredGithubFiles.map((file) => {
                    const isSource = isGithubScannablePath(file.path);
                    const language = githubLanguageLabel(file.path);
                    return (
                      <div
                        key={file.path}
                        className={cn(
                          "grid grid-cols-[44px_1fr_120px] items-center border-t border-border/50 px-3 py-2 text-sm",
                          !isSource && "opacity-45"
                        )}
                      >
                        <Checkbox
                          checked={selectedGithubFiles.has(file.path)}
                          disabled={!isSource}
                          onCheckedChange={(checked) => {
                            setSelectedGithubFiles((prev) => {
                              const next = new Set(prev);
                              if (checked) next.add(file.path);
                              else next.delete(file.path);
                              return next;
                            });
                          }}
                        />
                        <div className="flex min-w-0 items-center gap-2">
                          <FileText className="h-4 w-4 shrink-0 text-muted-foreground" />
                          <span className="truncate font-medium">{file.path}</span>
                        </div>
                        <Badge variant="outline" className={cn("w-fit", githubLanguageBadgeClass(language))}>
                          {language}
                        </Badge>
                      </div>
                    );
                  })
                )}
              </div>
              <div className="flex items-center justify-between border-t border-border/60 px-3 py-2 text-xs text-muted-foreground">
                <span>{selectedSourceCount} file{selectedSourceCount === 1 ? "" : "s"} selected</span>
                <span>Showing {filteredGithubFiles.length} of {githubFiles.length} files</span>
              </div>
            </div>
          </div>
        </CardContent>
      );
    }

    // ── Team mode: use the selected team's connected repo ───────────────────
    if (isTeamMode && selectedApiTeam) {
      if (!selectedApiTeam.github_repo) {
        return (
          <CardContent className="pt-6">
            <div className="flex flex-col items-center gap-4 py-8">
              <Info className="h-8 w-8 text-muted-foreground" />
              <p className="text-sm text-muted-foreground text-center">
                No repository connected to <span className="font-medium">{selectedApiTeam.name}</span>.
              </p>
              <p className="text-xs text-muted-foreground text-center">
                Ask a team admin to connect a GitHub repository first.
              </p>
            </div>
          </CardContent>
        );
      }

      return (
        <CardContent className="pt-6 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h3 className="font-semibold">Team branch files</h3>
              <p className="text-sm text-muted-foreground">
                Files are loaded from the repository and branch configured on the Teams page.
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
              <Badge variant="outline" className="gap-1">
                <Github className="h-3.5 w-3.5" />
                {selectedApiTeam.github_repo.replace("https://github.com/", "")}
              </Badge>
              <Badge variant="outline" className="gap-1">
                <GitBranch className="h-3.5 w-3.5" />
                {branch || selectedApiTeam.github_branches[0] || "No branch"}
              </Badge>
            </div>
          </div>

          <div className="rounded-lg border border-border/50 bg-background/30">
            <div className="flex items-center justify-between border-b border-border/50 bg-muted/20 px-3 py-2">
              <div className="flex items-center gap-2">
                <Badge variant="secondary" className="text-[10px] font-normal">
                  {teamGithubSourceFiles.length} scannable files
                </Badge>
                <Badge variant="secondary" className="text-[10px] font-normal">
                  {selectedTeamGithubFiles.size} selected
                </Badge>
              </div>
              {teamGithubFilesLoading && <Loader2 className="h-4 w-4 animate-spin text-primary" />}
            </div>

            {teamGithubFilesError && (
              <p className="px-3 py-3 text-sm text-destructive">{teamGithubFilesError}</p>
            )}

            {!teamGithubFilesLoading && !teamGithubFilesError && (
              <div className="divide-y divide-border/50">
                {teamGithubSourceFiles.length === 0 ? (
                  <p className="px-3 py-4 text-sm text-muted-foreground">No C/C++ files or ZIP archives found in the selected team branch.</p>
                ) : (
                  teamGithubSourceFiles.map((file) => {
                    const checked = selectedTeamGithubFiles.has(file.path);
                    const language = githubLanguageLabel(file.path);
                    return (
                      <label key={file.path} className="grid cursor-pointer grid-cols-[32px_minmax(220px,1fr)_140px_90px] items-center gap-3 px-3 py-2 hover:bg-muted/20">
                        <Checkbox
                          checked={checked}
                          onCheckedChange={(value) => {
                            setSelectedTeamGithubFiles((prev) => {
                              const next = new Set(prev);
                              if (value) next.add(file.path);
                              else next.delete(file.path);
                              return next;
                            });
                          }}
                        />
                        <div className="min-w-0">
                          <p className="truncate text-sm font-medium">{file.path}</p>
                        </div>
                        <Badge variant="outline" className={cn("w-fit", githubLanguageBadgeClass(language))}>
                          {language}
                        </Badge>
                        <span className="text-right text-xs text-muted-foreground">{formatFileSize(file.size ?? 0)}</span>
                      </label>
                    );
                  })
                )}
              </div>
            )}
          </div>
        </CardContent>
      );
    }

    return (
      <CardContent className="pt-6">
        <div className="flex flex-col items-center gap-4 py-8">
          <Info className="h-8 w-8 text-muted-foreground" />
          <p className="text-sm text-muted-foreground text-center">
            Select a team before importing from GitHub in team scan mode.
          </p>
        </div>
      </CardContent>
    );
  };

  // If scanning or complete, show split-screen view
  // The stream/result/error data is authoritative evidence that a scan view
  // exists. Do not drop back to the setup form merely because React processes
  // the persisted status flags in separate renders.
  const hasLiveScanView =
    isScanning ||
    scanComplete ||
    Boolean(scanError) ||
    Boolean(scanResult) ||
    displayedChunks.length > 0;

  if (hasLiveScanView && showLiveScan) {
    if (autoRescanPreparing) {
      return (
        <DashboardLayout>
          <div className="flex min-h-[calc(100vh-8rem)] items-center justify-center">
            <div className="flex flex-col items-center gap-4 rounded-lg border border-border/60 bg-card/60 px-10 py-8 text-center shadow-xl">
              <Loader2 className="h-10 w-10 animate-spin text-primary" />
              <div>
                <h2 className="text-lg font-semibold text-foreground">Preparing project sources</h2>
                <p className="mt-1 text-sm text-muted-foreground">
                  Extracting stored C/C++ files for rescan...
                </p>
              </div>
            </div>
          </div>
        </DashboardLayout>
      );
    }

    const firstFile = uploadedFiles[0];
    const displayName = effectiveProjectName
      ? `${effectiveProjectName}${firstFile ? ` · ${firstFile.name}` : ""}`
      : firstFile?.name || "Code Analysis";
    const showSourceLoader =
      isScanning &&
      uploadedFiles.some((file) => file.name.toLowerCase().endsWith(".zip")) &&
      codeLines.length === 1 &&
      !codeLines[0]?.content.trim();

    return (
      <DashboardLayout>
        <div className="h-[calc(100vh-4rem)] -m-4 lg:-m-6 flex flex-col">
          {/* Compact Header with Inline Progress */}
          <div className="flex items-center justify-between gap-3 px-3 py-2 border-b border-border/50 bg-background h-14 shrink-0">
            <div className="flex items-center gap-3 min-w-0">
              <Button
                variant="ghost"
                size="icon"
                className="shrink-0 h-8 w-8"
                onClick={() => isScanning ? setShowLiveScan(false) : handleReset()}
              >
                <ArrowLeft className="h-4 w-4" />
              </Button>
              <div className="flex items-center gap-2 min-w-0">
                <Shield className="h-4 w-4 text-primary shrink-0" />
                <span className="font-medium text-sm truncate max-w-[200px]">
                  {displayName}
                </span>
                {isTeamMode && (
                  <span className="bg-primary/20 text-primary text-xs px-2 py-0.5 rounded-full font-medium shrink-0">
                    Team
                  </span>
                )}
              </div>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <Button 
                variant="ghost" 
                size="icon" 
                className="h-8 w-8"
                onClick={() => setShowPanel(!showPanel)}
              >
                {showPanel ? (
                  <PanelLeftClose className="h-4 w-4" />
                ) : (
                  <PanelLeft className="h-4 w-4" />
                )}
              </Button>
              {isScanning && (
                <Button variant="destructive" size="sm" className="h-8" onClick={handleStopScan}>
                  <StopCircle className="h-4 w-4" />
                </Button>
              )}
              {scanComplete && !showPanel && (
                <Button variant="outline" size="sm" className="h-8" onClick={handleReset}>
                  New Scan
                </Button>
              )}
            </div>
          </div>

          {/* Main Content */}
          <div className="flex-1 flex overflow-hidden relative">
            {/* Left Panel - Collapsible */}
            <div 
              className={cn(
                "w-[280px] shrink-0 border-r border-emerald-500/20 bg-[#080d15] flex flex-col transition-all duration-300",
                showPanel ? "translate-x-0" : "-translate-x-full absolute -left-[280px]"
              )}
            >
              <div className="flex-1 overflow-y-auto">
                <ScanningProgress
                  currentPhase={currentPhase}
                  stats={stats}
                  isComplete={scanComplete}
                />
              </div>
              
              {/* Sticky Action Buttons */}
              <div className="p-3 border-t border-emerald-500/15 bg-[#111820]/95 backdrop-blur-sm">
                {scanComplete ? (
                  <Button variant="outline" size="sm" className="w-full" onClick={handleReset}>
                    New Scan
                  </Button>
                ) : (
                  <Button
                    variant="outline"
                    size="sm"
                    className="w-full border-destructive/40 bg-destructive/5 text-destructive hover:bg-destructive/10 hover:text-destructive"
                    onClick={handleStopScan}
                  >
                    <StopCircle className="h-4 w-4 mr-2" />
                    Stop
                  </Button>
                )}
              </div>
            </div>

            {/* Right Panel - Code Viewer / Report */}
            <div 
              className={cn(
                "flex-1 min-w-0 flex flex-col bg-muted/20 overflow-hidden transition-all duration-300",
                !showPanel && "ml-0"
              )}
            >
              {scanComplete && scanError ? (
                <div ref={scanOutputRef} className="flex-1 overflow-y-auto p-4 lg:p-6">
                  <div className="mx-auto max-w-3xl">
                    <Card className="bg-card/80 border-destructive/40 p-6">
                      <div className="flex items-start gap-3">
                        <AlertTriangle className="h-5 w-5 text-destructive mt-0.5" />
                        <div className="space-y-2">
                          <h2 className="text-lg font-semibold text-foreground">Analysis could not complete</h2>
                          <p className="text-sm text-muted-foreground">
                            {scanError === ZIP_NO_SOURCE_MESSAGE
                              ? "Upload a ZIP that includes at least one C or C++ source file. Other file types inside the ZIP are ignored automatically."
                              : isRenameFileError(scanError)
                              ? "Rename the flagged file, rebuild the ZIP if needed, and upload it again."
                              : "The security model did not return a valid report, so no analyzer-only findings were shown."}
                          </p>
                          <div className="mt-3 rounded-md bg-background/80 border border-border/50 p-3 text-sm text-foreground">
                            {scanError}
                          </div>
                          <Button className="mt-3" onClick={handleReset}>
                            Back to New Scan
                          </Button>
                        </div>
                      </div>
                    </Card>
                  </div>
                </div>
              ) : scanResult ? (
                <div className="flex-1 overflow-y-auto p-4 lg:p-6">
                  <div className="mx-auto grid max-w-7xl gap-5 xl:grid-cols-[minmax(0,1fr)_340px]">
                    <div className="space-y-5">
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
                      <Card className="overflow-hidden border-red-500/30 bg-gradient-to-br from-red-500/18 via-card/80 to-card/70 p-4 shadow-lg shadow-red-950/15">
                        <p className="text-xs text-muted-foreground">Risk</p>
                        <p className="mt-1 text-xl font-semibold text-red-100">{scanResult.overall_risk_level}</p>
                      </Card>
                      <Card className="overflow-hidden border-rose-500/30 bg-gradient-to-br from-rose-500/18 via-card/80 to-card/70 p-4 shadow-lg shadow-rose-950/15">
                        <p className="text-xs text-muted-foreground">Vulnerabilities</p>
                        <p className="mt-1 text-xl font-semibold text-rose-100">{scanResult.total_vulnerabilities}</p>
                      </Card>
                      <Card className="overflow-hidden border-cyan-500/30 bg-gradient-to-br from-cyan-500/18 via-card/80 to-card/70 p-4 shadow-lg shadow-cyan-950/15">
                        <p className="text-xs text-muted-foreground">Files</p>
                        <p className="mt-1 text-xl font-semibold text-cyan-100">{scanResult.files_analyzed}</p>
                      </Card>
                      <Card className="overflow-hidden border-violet-500/30 bg-gradient-to-br from-violet-500/18 via-card/80 to-card/70 p-4 shadow-lg shadow-violet-950/15">
                        <p className="text-xs text-muted-foreground">Score</p>
                        <p className="mt-1 text-xl font-semibold text-violet-100">{scanResult.overall_risk_score}</p>
                      </Card>
                    </div>

                    {displayedChunks.length > 0 && (
                      <Card className="bg-card/70 border-border/50 overflow-hidden">
                        <div className="p-4 border-b border-border/50">
                          <h2 className="text-lg font-semibold text-foreground">
                            {getChunkReportTitle(displayedChunks)}
                          </h2>
                          <p className="text-sm text-muted-foreground mt-1">
                            Source chunks open as results stream in.
                          </p>
                        </div>
                        <Accordion type="multiple" value={openChunkItems} className="divide-y divide-border/40">
                          {displayedChunks.map((chunk) => (
                            <AccordionItem key={`${chunk.file_path}-${chunk.chunk_index}`} value={`${chunk.file_path}-${chunk.chunk_index}`} className="border-0 px-4">
                              <AccordionTrigger className="hover:no-underline">
                                <div className="flex flex-wrap items-center gap-2 text-left">
                                  <Badge variant="outline">{chunk.file_path || chunk.chunk_name || `Chunk ${chunk.chunk_index}`}</Badge>
                                  <span className="font-medium text-foreground">
                                    Lines {chunk.start_line} to {chunk.end_line}
                                  </span>
                                  <Badge variant={chunk.vulnerabilities.length > 0 ? "destructive" : "outline"}>
                                    {chunk.vulnerabilities.length} issue{chunk.vulnerabilities.length === 1 ? "" : "s"}
                                  </Badge>
                                  {isScanning && chunk.corrected_code === "Pending..." && (
                                    <Badge variant="outline" className="animate-pulse border-primary/40 text-primary">
                                      streaming
                                    </Badge>
                                  )}
                                </div>
                              </AccordionTrigger>
                              <AccordionContent>
                                <div className="space-y-5 pb-4">
                                  <div>
                                    <p className="text-xs font-medium uppercase text-muted-foreground">Input code</p>
                                    <NumberedCodeBlock
                                      code={chunk.code}
                                      startLine={chunk.start_line}
                                      emptyText="No input code returned."
                                    />
                                  </div>

                                  <div className="space-y-3">
                                    <p className="text-xs font-medium uppercase text-muted-foreground">Vulnerabilities</p>
                                    {chunk.vulnerabilities.length === 0 ? (
                                      chunk.analysis_complete ? (
                                        <p className="rounded-md border border-border/50 bg-background/60 p-3 text-sm text-muted-foreground">
                                          No vulnerabilities were reported after this chunk was fully reviewed.
                                        </p>
                                      ) : (
                                        <div className="rounded-md border border-primary/25 bg-primary/5 p-3">
                                          <p className="text-sm font-medium text-primary">Model analysis is streaming...</p>
                                          <pre className="mt-2 max-h-48 overflow-auto whitespace-pre-wrap break-words font-mono text-xs text-muted-foreground">
                                            {chunk.model_output || "Waiting for the first model token..."}
                                          </pre>
                                        </div>
                                      )
                                    ) : (
                                      chunk.vulnerabilities.map((vulnerability, index) => (
                                        <div key={`${chunk.chunk_index}-${vulnerability.cwe_id}-${index}`} className="rounded-md border border-border/50 bg-background/70 p-4">
                                          <div className="flex flex-wrap items-center gap-2">
                                            <Badge variant="outline" className={cn(
                                              vulnerability.severity === "Critical" && "bg-red-500/15 text-red-300 border-red-500/30",
                                              vulnerability.severity === "High" && "bg-orange-500/15 text-orange-300 border-orange-500/30",
                                              vulnerability.severity === "Medium" && "bg-yellow-500/15 text-yellow-300 border-yellow-500/30",
                                              vulnerability.severity === "Low" && "bg-blue-500/15 text-blue-300 border-blue-500/30"
                                            )}>
                                              {vulnerability.severity}
                                            </Badge>
                                            <span className="font-semibold text-foreground">{vulnerability.cwe_id}</span>
                                            {vulnerability.line_number > 0 && (
                                              <span className="text-xs text-muted-foreground">line {vulnerability.line_number}</span>
                                            )}
                                          </div>
                                          <NumberedCodeBlock
                                            code={codeForVulnerability(chunk, vulnerability)}
                                            startLine={vulnerability.line_number || vulnerability.absolute_line || chunk.start_line}
                                          />
                                          <p className="mt-3 text-sm text-foreground">{vulnerability.description}</p>
                                        </div>
                                      ))
                                    )}
                                  </div>

                                  <div>
                                    <p className="text-xs font-medium uppercase text-muted-foreground">Corrected code</p>
                                    <NumberedCodeBlock
                                      code={chunk.corrected_code && chunk.corrected_code !== "None" ? chunk.corrected_code : ""}
                                      startLine={chunk.start_line}
                                      emptyText="Waiting for corrected code..."
                                    />
                                  </div>
                                </div>
                              </AccordionContent>
                            </AccordionItem>
                          ))}
                        </Accordion>
                      </Card>
                    )}

                    <div className="hidden grid-cols-1 gap-5">
                      <Card className="bg-card/70 border-border/50 overflow-hidden">
                        <div className="p-4 border-b border-border/50">
                          <h2 className="text-lg font-semibold text-foreground">Vulnerability Report</h2>
                          <p className="text-sm text-muted-foreground mt-1">
                            Each issue shows the exact line, affected code, problem, and fix.
                          </p>
                        </div>
                        <div className="divide-y divide-border/40">
                          {scanResult.vulnerabilities.length === 0 ? (
                            <div className="p-6 text-sm text-muted-foreground">No vulnerabilities were reported by the model.</div>
                          ) : (
                            scanResult.vulnerabilities.map((vulnerability, index) => (
                              <button
                                key={`${vulnerability.file_path}-${vulnerability.cwe_id}-${index}`}
                                className={cn(
                                  "w-full text-left p-5 hover:bg-muted/30 transition-colors",
                                  selectedVulnerability === vulnerability && "bg-primary/10"
                                )}
                                onClick={() => setSelectedVulnerability(vulnerability)}
                              >
                                <div className="flex flex-wrap items-center gap-2">
                                  <span className="text-sm font-semibold text-foreground">Issue {index + 1}</span>
                                  <Badge variant="outline" className={cn(
                                    vulnerability.severity === "Critical" && "bg-red-500/15 text-red-300 border-red-500/30",
                                    vulnerability.severity === "High" && "bg-orange-500/15 text-orange-300 border-orange-500/30",
                                    vulnerability.severity === "Medium" && "bg-yellow-500/15 text-yellow-300 border-yellow-500/30",
                                    vulnerability.severity === "Low" && "bg-blue-500/15 text-blue-300 border-blue-500/30"
                                  )}>
                                    {vulnerability.severity}
                                  </Badge>
                                  <span className="font-semibold text-foreground">{vulnerability.cwe_id}</span>
                                  <span className="text-sm text-muted-foreground">{vulnerability.cwe_name}</span>
                                </div>
                                <div className="mt-4 grid gap-4 lg:grid-cols-[220px_minmax(0,1fr)]">
                                  <div>
                                    <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Line</p>
                                    <p className="mt-1 text-sm font-medium text-foreground">
                                      {vulnerability.file_path}
                                      {vulnerability.line_number ? `, line ${vulnerability.line_number}` : ""}
                                    </p>
                                    {vulnerability.location && (
                                      <p className="mt-1 text-xs text-muted-foreground">{vulnerability.location}</p>
                                    )}
                                  </div>

                                  <div className="space-y-4">
                                    <div>
                                      <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Code at this line</p>
                                      <NumberedCodeBlock
                                        code={vulnerability.affected_code || `Line ${vulnerability.line_number || vulnerability.absolute_line || "N/A"}`}
                                        startLine={vulnerability.line_number || vulnerability.absolute_line || 1}
                                      />
                                    </div>
                                    <div>
                                      <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">What is vulnerable here</p>
                                      <p className="mt-1 text-sm text-foreground">{vulnerability.description}</p>
                                    </div>
                                    <div>
                                      <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Recommended fix</p>
                                      <p className="mt-1 text-sm text-foreground">{vulnerability.fix_suggestion}</p>
                                    </div>
                                  </div>
                                </div>
                              </button>
                            ))
                          )}
                        </div>
                      </Card>

                      <Card className="hidden">
                        <h3 className="font-semibold text-foreground">Finding Details</h3>
                        {selectedVulnerability ? (
                          <>
                            <div>
                              <p className="text-xs text-muted-foreground">Location</p>
                              <p className="text-sm text-foreground mt-1">
                                {selectedVulnerability.file_path}
                                {selectedVulnerability.location ? ` — ${selectedVulnerability.location}` : ""}
                              </p>
                            </div>
                            <div>
                              <p className="text-xs text-muted-foreground">Affected Code</p>
                              <NumberedCodeBlock
                                code={selectedVulnerability.affected_code || `Line ${selectedVulnerability.line_number || selectedVulnerability.absolute_line || "N/A"}`}
                                startLine={selectedVulnerability.line_number || selectedVulnerability.absolute_line || 1}
                              />
                            </div>
                            <div>
                              <p className="text-xs text-muted-foreground">Remediation</p>
                              <p className="text-sm text-foreground mt-1">{selectedVulnerability.fix_suggestion}</p>
                            </div>
                          </>
                        ) : (
                          <p className="text-sm text-muted-foreground">Select a vulnerability from the report.</p>
                        )}
                      </Card>
                    </div>

                    <Card className="hidden bg-card/70 border-border/50 overflow-hidden">
                      <div className="p-4 border-b border-border/50">
                        <h2 className="text-lg font-semibold text-foreground">Corrected Code</h2>
                        <p className="text-sm text-muted-foreground mt-1">Model-generated secure version.</p>
                      </div>
                      <div className="divide-y divide-border/40 bg-background/70">
                        {(scanResult.files?.length ? scanResult.files : [{ filename: "corrected-code", language: "", corrected_code: scanResult.corrected_code }]).map((file, index) => (
                          <section key={`${file.filename}-${index}`}>
                            <div className="flex items-center justify-between px-4 py-2 bg-background/80">
                              <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">
                                {file.filename}
                              </span>
                              {file.language && (
                                <Badge variant="outline" className="text-[10px]">
                                  {file.language}
                                </Badge>
                              )}
                            </div>
                            <NumberedCodeBlock
                              code={file.corrected_code && file.corrected_code !== "None" ? file.corrected_code : ""}
                              emptyText="No corrected code was returned."
                            />
                          </section>
                        ))}
                      </div>
                    </Card>
                    </div>
                    <Card className="bg-card/70 border-border/60 overflow-hidden h-fit xl:sticky xl:top-4">
                      <div className="p-4 border-b border-border/50">
                        <div className="flex items-center gap-2">
                          <Sparkles className="h-4 w-4 text-primary" />
                          <h2 className="text-base font-semibold text-foreground">Thinking</h2>
                        </div>
                        <p className="text-xs text-muted-foreground mt-1">Live node stream and model progress.</p>
                      </div>
                      <div className="max-h-[calc(100vh-12rem)] overflow-y-auto p-4">
                        {renderThinkingStream("No thinking events were recorded.")}
                      </div>
                    </Card>
                  </div>
                </div>
              ) : (
                <div className="flex-1 p-4 lg:p-6 overflow-hidden">
                  <div className="grid h-full gap-4 xl:grid-cols-[minmax(0,1fr)_360px]">
                    {showSourceLoader ? (
                      <div className="grid h-full place-items-center rounded-lg border border-border/30 bg-[#0d1117]">
                        <Loader2 className="h-10 w-10 animate-spin text-primary" />
                      </div>
                    ) : isScanning && codeLines.length === 0 ? (
                      <div className="flex h-full flex-col rounded-lg border border-border/30 bg-[#0d1117]">
                        <div className="flex items-center justify-between border-b border-white/10 px-4 py-3">
                          <div className="flex items-center gap-2">
                            <Radar className="h-4 w-4 text-primary" />
                            <span className="font-mono text-sm font-semibold text-foreground">
                              Preparing source package
                            </span>
                          </div>
                          <Badge variant="outline" className="border-primary/30 text-primary">
                            live
                          </Badge>
                        </div>
                        <div className="flex flex-1 items-center justify-center p-6">
                          <div className="w-full max-w-xl space-y-5 text-center">
                            <div className="mx-auto grid h-16 w-16 place-items-center rounded-lg border border-primary/30 bg-primary/10">
                              <Loader2 className="h-8 w-8 animate-spin text-primary" />
                            </div>
                            <div>
                              <h2 className="text-lg font-semibold text-foreground">
                                Source files are being reviewed
                              </h2>
                              <p className="mt-1 text-sm text-muted-foreground">
                                {isUploadScan
                                  ? `Preparing ${queuedFileCount || 1} uploaded source file${(queuedFileCount || 1) === 1 ? "" : "s"}, chunking code, and streaming results.`
                                  : "Discovering repository files, chunking code, and streaming results."}
                              </p>
                            </div>
                            {branchFiles.length > 0 ? (
                              <div className="rounded-md border border-border/40 bg-background/50 text-left">
                                <div className="flex items-center justify-between border-b border-border/40 px-3 py-2">
                                  <span className="text-xs font-semibold uppercase text-muted-foreground">
                                    Files queued
                                  </span>
                                  <span className="text-xs text-primary">{branchFiles.length}</span>
                                </div>
                                <div className="max-h-48 overflow-y-auto p-2">
                                  {branchFiles.slice(0, 8).map((filePath) => (
                                    <div key={filePath} className="flex items-center gap-2 rounded px-2 py-1.5 text-sm text-foreground">
                                      <FileUp className="h-3.5 w-3.5 shrink-0 text-primary" />
                                      <span className="truncate font-mono text-xs">{filePath}</span>
                                    </div>
                                  ))}
                                  {branchFiles.length > 8 && (
                                    <p className="px-2 py-1 text-xs text-muted-foreground">
                                      {branchFiles.length - 8} more file{branchFiles.length - 8 === 1 ? "" : "s"} queued
                                    </p>
                                  )}
                                </div>
                              </div>
                            ) : (
                              <div className="space-y-2">
                                <div className="h-2 overflow-hidden rounded-full bg-muted">
                                  <div className="h-full w-1/2 animate-global-scan-progress rounded-full bg-primary" />
                                </div>
                                <p className="text-xs text-muted-foreground">
                                  {isUploadScan ? "Waiting for uploaded source stream..." : "Waiting for source discovery..."}
                                </p>
                              </div>
                            )}
                          </div>
                        </div>
                      </div>
                    ) : (
                      <CodeViewer
                        lines={codeLines}
                        currentLine={currentLine}
                        language={firstFile ? scanLang : "c"}
                      />
                    )}
                    <Card className="bg-card/70 border-border/60 overflow-hidden h-full">
                      <div className="p-4 border-b border-border/50">
                        <div className="flex items-center gap-2">
                          <Boxes className="h-4 w-4 text-primary" />
                          <h2 className="text-base font-semibold text-foreground">Thinking</h2>
                        </div>
                        <p className="text-xs text-muted-foreground mt-1">Processing semantic chunks one at a time.</p>
                      </div>
                      <div className="p-4 overflow-y-auto max-h-full">
                        {renderThinkingStream("Waiting for analysis to start.")}
                      </div>
                    </Card>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </DashboardLayout>
    );
  }

  // Pre-scan UI
  return (
    <DashboardLayout>
      <div className="space-y-6 max-w-4xl mx-auto">
        {/* Page Header */}
        <div className="relative overflow-hidden rounded-2xl bg-gradient-to-br from-primary/10 via-background to-background border border-primary/20 p-8">
          <div className="absolute inset-0 bg-grid-pattern opacity-5" />
          <div className="relative">
            <div className="flex items-center gap-3 mb-2">
              <div className="p-2 rounded-lg bg-primary/20">
                <Shield className="h-6 w-6 text-primary" />
              </div>
              <h1 className="text-2xl lg:text-3xl font-bold text-foreground">
                New Security Scan
              </h1>
            </div>
            <p className="text-muted-foreground max-w-lg">
              Upload your C or C++ code to detect vulnerabilities, 
              security flaws, and potential exploits using AI-powered analysis.
            </p>
          </div>
        </div>

        {/* ── Scan Mode Toggle ─────────────────────────────────────────── */}
        <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
          <CardContent className="pt-6 space-y-4">
            {/* Personal / Team toggle */}
            <div className="flex items-center gap-1 p-1 rounded-lg bg-muted/50 border border-border/50 w-fit">
              <Button
                size="sm"
                variant={scanMode === "personal" ? "default" : "ghost"}
                className="h-8 px-4 text-xs font-medium"
                onClick={() => {
                  setScanMode("personal");
                }}
              >
                Personal Scan
              </Button>
              <Button
                size="sm"
                variant={scanMode === "team" ? "default" : "ghost"}
                className="h-8 px-4 text-xs font-medium"
                onClick={() => {
                  if (allTeams.length === 0) {
                    toast.error("No Teams Found", {
                      description: "You must be a member of a team to perform a team scan.",
                    });
                    return;
                  }
                  setScanMode("team");
                }}
              >
                Team Scan
              </Button>
            </div>

            {/* ── TEAM MODE: team selector + role gate ─────────────────── */}
            {scanMode === "team" && (
              <div className="space-y-3 mb-4">
                <Label className="text-sm font-medium">
                  Team <span className="text-destructive">*</span>
                </Label>
                <Select value={selectedTeamId} onValueChange={setSelectedTeamId}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select a team" />
                  </SelectTrigger>
                  <SelectContent>
                    {allTeams.map((team) => (
                      <SelectItem key={team.id} value={team.id}>
                        <span className="flex items-center gap-2">
                          {team.current_user_role === "admin" && (
                            <Crown className="h-3.5 w-3.5 text-yellow-500 shrink-0" />
                          )}
                          {team.current_user_role === "viewer" && (
                            <Eye className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                          )}
                          <span className="truncate">{team.name}</span>
                          <Badge
                            variant="outline"
                            className={cn(
                              "text-[10px] px-1.5 py-0 h-4 capitalize ml-1",
                              team.current_user_role === "admin" && "bg-primary/20 text-primary border-primary/30",
                              team.current_user_role === "developer" && "bg-blue-500/20 text-blue-400 border-blue-500/30",
                              team.current_user_role === "viewer" && "bg-muted text-muted-foreground border-border"
                            )}
                          >
                            {team.current_user_role}
                          </Badge>
                        </span>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>

                {/* Viewer blocked message */}
                {isViewer && (
                  <div className="flex items-start gap-3 p-4 rounded-lg bg-amber-500/10 border border-amber-500/20">
                    <Eye className="h-5 w-5 text-amber-400 shrink-0 mt-0.5" />
                    <div>
                      <p className="text-sm font-medium text-amber-400">
                        View-only access
                      </p>
                      <p className="text-xs text-muted-foreground mt-1">
                        You have Viewer access in this team and cannot initiate scans.
                        Contact your team Admin to upgrade your role to Developer or Admin.
                      </p>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* ── PROJECT SELECTOR (Both Modes) ──────────────────────── */}
            {(scanMode === "personal" || (scanMode === "team" && canScanInTeam)) && (
              <div className="space-y-3">
                <Label className="text-sm font-medium">
                  Project <span className="text-destructive">*</span>
                </Label>
                <Popover open={projectDropdownOpen} onOpenChange={setProjectDropdownOpen}>
                  <PopoverTrigger asChild>
                    <Button
                      variant="outline"
                      role="combobox"
                      aria-expanded={projectDropdownOpen}
                      className="w-full justify-between font-normal"
                    >
                      {selectedProjectId
                        ? selectedProjectId === "__new__"
                          ? "Create new project"
                          : projects.find((project) => project.id === selectedProjectId)?.name
                        : "Select or create a project"}
                      <ChevronsUpDown className="ml-2 h-4 w-4 shrink-0 opacity-50" />
                    </Button>
                  </PopoverTrigger>
                  <PopoverContent className="w-[var(--radix-popover-trigger-width)] p-0" align="start">
                    <Command shouldFilter={false}>
                      <CommandInput 
                        placeholder="Search projects..." 
                        value={projectSearch}
                        onValueChange={setProjectSearch}
                      />
                      <CommandList>
                        <CommandEmpty>No project found.</CommandEmpty>
                        <CommandGroup>
                          <CommandItem
                            value="__new__"
                            onSelect={() => {
                              setSelectedProjectId("__new__");
                              setSelectedProjectName("");
                              setIsCreatingProject(true);
                              setUploadedFiles([]);
                              setFileContent("");
                              setProjectDropdownOpen(false);
                              setProjectSearch("");
                            }}
                          >
                            <div className="flex items-center gap-2 text-primary w-full">
                              <Plus className="h-3.5 w-3.5" />
                              <span>Create new project</span>
                              {selectedProjectId === "__new__" && (
                                <Check className="ml-auto h-4 w-4" />
                              )}
                            </div>
                          </CommandItem>
                          {projects
                            .filter((p) => scanMode === "personal" ? p.type === "personal" : (p.type === "team" && p.team_id === selectedTeamId))
                            .filter((p) => p.name.toLowerCase().includes(projectSearch.toLowerCase()))
                            .slice(0, 5)
                            .map((p) => (
                              <CommandItem
                                key={p.id}
                                value={p.name}
                                onSelect={() => {
                                  setSelectedProjectId(p.id);
                                  setSelectedProjectName(p.name);
                                  setIsCreatingProject(false);
                                  setNewProjectName("");
                                  setUploadedFiles([]);
                                  setFileContent("");
                                  setBranch("main");
                                  setProjectDropdownOpen(false);
                                  setProjectSearch("");
                                }}
                              >
                                {p.name}
                                {selectedProjectId === p.id && (
                                  <Check className="ml-auto h-4 w-4" />
                                )}
                              </CommandItem>
                            ))}
                        </CommandGroup>
                      </CommandList>
                    </Command>
                  </PopoverContent>
                </Popover>

                {/* Inline new project name input */}
                {selectedProjectId === "__new__" && (
                  <div className="space-y-1.5">
                    <Input
                      placeholder="Enter new project name"
                      value={newProjectName}
                      onChange={(e) => setNewProjectName(e.target.value)}
                      autoFocus
                      onKeyDown={(event) => {
                        if (event.key === "Enter") {
                          event.preventDefault();
                          handleCreateInlineProject();
                        }
                      }}
                    />
                    <div className="flex justify-end gap-2">
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        onClick={() => {
                          setSelectedProjectId("");
                          setSelectedProjectName("");
                          setNewProjectName("");
                          setIsCreatingProject(false);
                        }}
                        disabled={isProjectSubmitting}
                      >
                        Cancel
                      </Button>
                      <Button
                        type="button"
                        size="sm"
                        onClick={handleCreateInlineProject}
                        disabled={isProjectSubmitting || !newProjectName.trim()}
                      >
                        {isProjectSubmitting ? (
                          <Loader2 className="h-4 w-4 animate-spin" />
                        ) : (
                          "Create"
                        )}
                      </Button>
                    </div>
                    {detectedProjectLanguage && (
                      <p className="text-xs text-muted-foreground flex items-center gap-1.5">
                        Project will be created as
                        <span
                          className={cn(
                            "text-[10px] px-1.5 py-0 rounded-full border font-medium",
                            detectedProjectLanguage === "C"
                              ? "bg-purple-500/20 text-purple-400 border-purple-500/30"
                              : "bg-pink-500/20 text-pink-400 border-pink-500/30"
                          )}
                        >
                          {detectedProjectLanguage}
                        </span>
                        based on your uploaded file.
                      </p>
                    )}
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Source Selection Tabs */}
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="grid w-full grid-cols-2 h-12">
            <TabsTrigger value="upload" className="gap-2 text-sm font-medium">
              <Upload className="h-4 w-4" />
              Upload File
            </TabsTrigger>
            <TabsTrigger value="github" className="gap-2 text-sm font-medium">
              <Github className="h-4 w-4" />
              {isTeamMode ? "Select Team GitHub Files" : "Import from GitHub"}
            </TabsTrigger>
          </TabsList>

          {/* Upload Tab */}
          <TabsContent value="upload" className="mt-6">
            {/* ── Existing Project Files (real project selected) ── */}
            {selectedProjectId &&
              selectedProjectId !== "__new__" && (
                <Card className="border-border/50 bg-card/50 backdrop-blur-sm mb-4">
                  <CardHeader className="pb-3 pt-4 px-4">
                    <div className="flex items-center justify-between">
                      <CardTitle className="text-sm font-medium text-foreground">
                        Existing Files
                      </CardTitle>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-7 w-7"
                        onClick={() => fetchProjectFiles(selectedProjectId)}
                        disabled={projectFilesLoading}
                        title="Refresh files"
                      >
                        <RefreshCw
                          className={cn(
                            "h-3.5 w-3.5",
                            projectFilesLoading && "animate-spin"
                          )}
                        />
                      </Button>
                    </div>
                  </CardHeader>
                  <CardContent className="px-4 pb-4">
                    {projectFilesError && (
                      <p className="text-xs text-destructive mb-2">
                        {projectFilesError}
                      </p>
                    )}
                    {projectFilesLoading && projectFiles.length === 0 ? (
                      <p className="text-xs text-muted-foreground py-2">
                        Loading files…
                      </p>
                    ) : projectFiles.length === 0 ? (
                      <p className="text-xs text-muted-foreground py-2">
                        No files in this project yet.
                      </p>
                    ) : (
                      <div className="space-y-1">
                        {/* Select All header */}
                        <div className="flex items-center gap-3 px-2 py-1.5 rounded-md bg-muted/30 border border-border/40 mb-2">
                          <Checkbox
                            id="select-all-files"
                            checked={
                              projectFiles.length > 0 &&
                              projectFiles.every((f) => selectedFileIds.has(f.id))
                            }
                            onCheckedChange={(checked) => {
                              if (checked) {
                                setSelectedFileIds(
                                  new Set(projectFiles.map((f) => f.id))
                                );
                              } else {
                                setSelectedFileIds(new Set());
                              }
                            }}
                          />
                          <label
                            htmlFor="select-all-files"
                            className="text-xs font-medium text-muted-foreground cursor-pointer select-none flex-1"
                          >
                            Select All
                          </label>
                          <span className="text-xs text-muted-foreground">
                            {selectedFileIds.size}/{projectFiles.length} selected
                          </span>
                        </div>

                        {/* File rows */}
                        {projectFiles.map((file) => (
                          <div
                            key={file.id}
                            className={cn(
                              "flex items-center gap-3 px-2 py-2 rounded-md border transition-colors cursor-pointer",
                              selectedFileIds.has(file.id)
                                ? "bg-primary/5 border-primary/20"
                                : "bg-transparent border-border/30 hover:bg-muted/20"
                            )}
                            onClick={() => {
                              setSelectedFileIds((prev) => {
                                const next = new Set(prev);
                                if (next.has(file.id)) {
                                  next.delete(file.id);
                                } else {
                                  next.add(file.id);
                                }
                                return next;
                              });
                            }}
                          >
                            <Checkbox
                              checked={selectedFileIds.has(file.id)}
                              onCheckedChange={(checked) => {
                                setSelectedFileIds((prev) => {
                                  const next = new Set(prev);
                                  if (checked) {
                                    next.add(file.id);
                                  } else {
                                    next.delete(file.id);
                                  }
                                  return next;
                                });
                              }}
                              onClick={(e) => e.stopPropagation()}
                            />
                            <span className="text-sm font-medium text-foreground truncate flex-1 min-w-0">
                              {file.name}
                            </span>
                            <span className="text-xs text-muted-foreground shrink-0 w-16 text-right">
                              {formatFileSize(file.size)}
                            </span>
                            <span className="text-xs text-muted-foreground shrink-0 w-24 text-right">
                              {formatRelativeTime(file.uploaded_at)}
                            </span>
                          </div>
                        ))}
                      </div>
                    )}
                  </CardContent>
                </Card>
              )}

            {shouldShowUploadCard && (
            <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
              <CardContent className="pt-6">
                {/* Language lock notice */}
                {effectiveLanguage && (
                  <div className="flex items-center gap-2 mb-4 px-1">
                    <span className="text-xs text-muted-foreground">
                      Language locked to
                    </span>
                    <span
                      className={cn(
                        "text-[10px] px-1.5 py-0.5 rounded-full border font-medium",
                        effectiveLanguage === "C"
                          ? "bg-purple-500/20 text-purple-400 border-purple-500/30"
                          : "bg-pink-500/20 text-pink-400 border-pink-500/30"
                      )}
                    >
                      {effectiveLanguage}
                    </span>
                    <span className="text-xs text-muted-foreground">
                      — only {acceptedExtensions} files accepted
                    </span>
                  </div>
                )}
                <FileUploadArea
                  uploadedFiles={uploadedFiles}
                  isDragOver={isDragOver}
                  onDragOver={handleDragOver}
                  onDragLeave={handleDragLeave}
                  onDrop={handleDrop}
                  onFileSelect={handleFileSelect}
                  onRemoveFile={handleRemoveFile}
                  lockedLanguage={effectiveLanguage}
                  compactSelected
                />

                {/* "Save to project" toggles — show whenever a project is selected or being created */}
                {false && selectedProjectId &&
                  uploadedFiles.length > 0 && (
                    <div className="mt-4 space-y-2">
                      {uploadedFiles.map((file, index) => {
                        const badge = getFileLangBadge(file.name);
                        return (
                          <div
                            key={`save-${file.name}-${index}`}
                            className="flex items-center gap-2 px-1"
                          >
                            <Checkbox
                              id={`save-to-project-${index}`}
                              checked={saveToProject[index] !== false}
                              onCheckedChange={(checked) =>
                                setSaveToProject((prev) => ({
                                  ...prev,
                                  [index]: !!checked,
                                }))
                              }
                            />
                            <label
                              htmlFor={`save-to-project-${index}`}
                              className="text-xs text-muted-foreground cursor-pointer select-none flex items-center gap-1.5"
                            >
                              Save{" "}
                              <span className="font-medium text-foreground">
                                {file.name}
                              </span>
                              {badge && (
                                <span
                                  className={cn(
                                    "text-[10px] px-1.5 py-0 rounded-full border font-medium",
                                    badge.className
                                  )}
                                >
                                  {badge.label}
                                </span>
                              )}
                              {" "}to project
                            </label>
                          </div>
                        );
                      })}
                    </div>
                  )}
              </CardContent>
            </Card>
            )}
          </TabsContent>

          {/* GitHub Tab */}
          <TabsContent value="github" className="mt-6">
            <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
              {renderGitHubTab()}
            </Card>
          </TabsContent>
        </Tabs>

        {/* Start Analysis Button */}
        <Button 
          size="lg" 
          className="w-full h-14 text-lg font-semibold shadow-lg shadow-primary/25 hover:shadow-xl hover:shadow-primary/30 transition-all"
          onClick={handleStartScan}
          disabled={!canStartScan}
        >
          <Play className="h-5 w-5 mr-2" />
          Start Security Analysis
        </Button>
      </div>
    </DashboardLayout>
  );
};

export default NewScan;
