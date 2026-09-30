import { useMutation, useQuery } from "@tanstack/react-query";
import clsx from "clsx";
import { FileArchive, GitBranch, UploadCloud } from "lucide-react";
import { useRef, useState, type DragEvent, type FormEvent } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { Card, ErrorBox, Field, Notice, PageHeader, Tabs } from "../../components/ui";
import { api, uploadWithProgress } from "../../lib/api";
import { formatBytes, relativeTime } from "../../lib/format";
import type { Page, Repository, Scan } from "../../lib/types";

type Scanner = "sast" | "secrets" | "dependencies";
const SCANNERS: { id: Scanner; name: string; help: string }[] = [
  { id: "sast", name: "Code (SAST)", help: "Data-flow analysis for Python, JS/TS, PHP, Java, C#, Go, C/C++" },
  { id: "secrets", name: "Secrets", help: "Credentials in code and config; values are always masked" },
  { id: "dependencies", name: "Dependencies", help: "Manifests and lock files, checked against advisories" },
];
const ACCEPT = ".zip,.tar,.tgz,.gz,.bz2,.xz,.py,.js,.ts,.tsx,.jsx,.php,.java,.cs,.go,.c,.cpp,.h,.hpp,.rb,.kt,.swift,.rs,.json,.yml,.yaml,.toml,.xml,.txt,.lock";

interface Options {
  scanners: Scanner[];
  exclude: string;
  external: boolean;
  baseline: string;
}

function ScanOptions({ options, setOptions, baselines }: { options: Options; setOptions: (o: Options) => void; baselines: Scan[] }) {
  const toggle = (id: Scanner) =>
    setOptions({ ...options, scanners: options.scanners.includes(id) ? options.scanners.filter((s) => s !== id) : [...options.scanners, id] });
  return (
    <div className="space-y-4">
      <div>
        <span className="label">Scanners</span>
        <div className="grid gap-2 sm:grid-cols-3">
          {SCANNERS.map((s) => (
            <label key={s.id} className={clsx("card flex cursor-pointer gap-3 p-3", options.scanners.includes(s.id) && "border-accent/60")}>
              <input type="checkbox" checked={options.scanners.includes(s.id)} onChange={() => toggle(s.id)} className="mt-1" />
              <span>
                <span className="block text-sm font-medium">{s.name}</span>
                <span className="block text-xs text-muted">{s.help}</span>
              </span>
            </label>
          ))}
        </div>
      </div>
      <Field label="Exclude paths (one glob per line)" hint="Added to the defaults (node_modules, vendor, build output…)">
        <textarea
          className="input font-mono"
          rows={2}
          placeholder={"tests/fixtures/**\ndocs/**"}
          value={options.exclude}
          onChange={(e) => setOptions({ ...options, exclude: e.target.value })}
        />
      </Field>
      <label className="flex items-center gap-2 text-sm">
        <input type="checkbox" checked={options.external} onChange={(e) => setOptions({ ...options, external: e.target.checked })} />
        Also run Bandit / Semgrep / Gitleaks when they are installed on the worker
      </label>
      <Field label="Compare with an earlier scan (retest)" hint="Shows what was resolved, what is still open and what is new.">
        <select className="input" value={options.baseline} onChange={(e) => setOptions({ ...options, baseline: e.target.value })}>
          <option value="">No comparison (the latest full scan of the same source is used automatically)</option>
          {baselines.map((s) => (
            <option key={s.id} value={s.id}>
              {s.repository_name ?? "scan"} · {s.stats.findings_total ?? 0} findings · {relativeTime(s.finished_at)}
            </option>
          ))}
        </select>
      </Field>
    </div>
  );
}

function configOf(options: Options) {
  return {
    scanners: options.scanners,
    exclude: options.exclude.split("\n").map((l) => l.trim()).filter(Boolean),
    external: options.external,
  };
}

export default function NewScan() {
  const { projectId = "" } = useParams();
  const navigate = useNavigate();
  const [tab, setTab] = useState<"upload" | "git">("upload");
  const [file, setFile] = useState<File | null>(null);
  const [repoName, setRepoName] = useState("");
  const [repoId, setRepoId] = useState("");
  const [branch, setBranch] = useState("");
  const [dragging, setDragging] = useState(false);
  const [progress, setProgress] = useState<number | null>(null);
  const [options, setOptions] = useState<Options>({ scanners: ["sast", "secrets", "dependencies"], exclude: "", external: true, baseline: "" });
  const input = useRef<HTMLInputElement>(null);

  const repositories = useQuery({ queryKey: ["repositories", projectId], queryFn: () => api.get<Repository[]>(`/projects/${projectId}/repositories`) });
  const baselines = useQuery({
    queryKey: ["scans", projectId, "completed"],
    queryFn: () => api.get<Page<Scan>>(`/projects/${projectId}/scans`, { status: "COMPLETED", page_size: 50 }),
  });
  const gitRepos = (repositories.data ?? []).filter((r) => r.source_type === "GIT");

  const upload = useMutation({
    mutationFn: () => {
      const form = new FormData();
      form.append("file", file!);
      if (repoName.trim()) form.append("repository_name", repoName.trim());
      if (options.baseline) form.append("baseline_scan_id", options.baseline);
      form.append("config", JSON.stringify(configOf(options)));
      setProgress(0);
      return uploadWithProgress<Scan>(`/projects/${projectId}/uploads`, form, setProgress);
    },
    onSuccess: (scan) => navigate(`/projects/${projectId}/scans/${scan.id}`),
    onSettled: () => setProgress(null),
  });
  const gitScan = useMutation({
    mutationFn: () =>
      api.post<Scan>(`/projects/${projectId}/scans`, {
        repository_id: repoId,
        branch: branch || null,
        config: configOf(options),
        baseline_scan_id: options.baseline || null,
      }),
    onSuccess: (scan) => navigate(`/projects/${projectId}/scans/${scan.id}`),
  });

  const onDrop = (event: DragEvent) => {
    event.preventDefault();
    setDragging(false);
    const dropped = event.dataTransfer.files[0];
    if (dropped) setFile(dropped);
  };
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (tab === "upload") upload.mutate();
    else gitScan.mutate();
  };
  const error = upload.error ?? gitScan.error;

  return (
    <>
      <PageHeader title="New scan" subtitle="Uploaded code is treated as untrusted: it is extracted safely and analysed in an isolated worker, never executed." />
      <form onSubmit={submit} className="grid gap-4 lg:grid-cols-5">
        <div className="lg:col-span-3">
          <Card>
            <Tabs
              tabs={[
                { id: "upload", label: <span className="flex items-center gap-2"><UploadCloud className="h-4 w-4" /> Upload code</span> },
                { id: "git", label: <span className="flex items-center gap-2"><GitBranch className="h-4 w-4" /> Git repository</span> },
              ]}
              value={tab}
              onChange={setTab}
            />
            {tab === "upload" ? (
              <div className="space-y-4">
                <div
                  onDragOver={(e) => {
                    e.preventDefault();
                    setDragging(true);
                  }}
                  onDragLeave={() => setDragging(false)}
                  onDrop={onDrop}
                  onClick={() => input.current?.click()}
                  className={clsx(
                    "flex cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed px-6 py-10 text-center transition-colors",
                    dragging ? "border-accent bg-accent/10" : "border-line hover:border-accent/60",
                  )}
                  role="button"
                  tabIndex={0}
                  aria-label="Choose a file to upload"
                  onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && input.current?.click()}
                >
                  <FileArchive className="mb-3 h-10 w-10 text-muted" />
                  {file ? (
                    <>
                      <div className="font-medium">{file.name}</div>
                      <div className="text-sm text-muted">{formatBytes(file.size)} · click to choose another file</div>
                    </>
                  ) : (
                    <>
                      <div className="font-medium">Drop a ZIP or TAR archive, or a single source file</div>
                      <div className="text-sm text-muted">Executables and binaries are rejected. Archives are checked for path traversal and bombs.</div>
                    </>
                  )}
                  <input ref={input} type="file" accept={ACCEPT} className="hidden" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
                </div>
                <Field label="Repository name" hint="Scans with the same name are compared over time. Defaults to the file name.">
                  <input className="input" value={repoName} onChange={(e) => setRepoName(e.target.value)} placeholder="shop-api" />
                </Field>
                {progress !== null && (
                  <div>
                    <div className="mb-1 flex justify-between text-xs text-muted">
                      <span>Uploading</span>
                      <span>{Math.round(progress * 100)}%</span>
                    </div>
                    <div className="h-2 overflow-hidden rounded-full bg-surface-3">
                      <div className="h-full bg-accent transition-all" style={{ width: `${progress * 100}%` }} />
                    </div>
                  </div>
                )}
              </div>
            ) : gitRepos.length === 0 ? (
              <Notice>
                No git repositories yet. <Link to={`/projects/${projectId}/repositories`} className="text-accent">Add one</Link> (HTTPS URL on an
                allow-listed host; private repositories use an integration token from the server environment).
              </Notice>
            ) : (
              <div className="space-y-4">
                <Field label="Repository">
                  <select className="input" value={repoId} onChange={(e) => setRepoId(e.target.value)} required>
                    <option value="">Choose…</option>
                    {gitRepos.map((r) => (
                      <option key={r.id} value={r.id}>
                        {r.name} — {r.url}
                      </option>
                    ))}
                  </select>
                </Field>
                <Field label="Branch" hint="Leave empty for the repository's default branch.">
                  <input className="input" value={branch} onChange={(e) => setBranch(e.target.value)} placeholder="main" />
                </Field>
              </div>
            )}
          </Card>
        </div>
        <div className="space-y-4 lg:col-span-2">
          <Card title="Options">
            <ScanOptions options={options} setOptions={setOptions} baselines={baselines.data?.items ?? []} />
          </Card>
          {error && <ErrorBox error={error} title="The scan could not be started" />}
          <button
            className="btn-primary w-full"
            disabled={
              options.scanners.length === 0 ||
              upload.isPending ||
              gitScan.isPending ||
              (tab === "upload" ? !file : !repoId)
            }
          >
            {upload.isPending || gitScan.isPending ? "Starting…" : "Start scan"}
          </button>
        </div>
      </form>
    </>
  );
}
