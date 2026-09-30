/**
 * API client. Authentication is the HttpOnly session cookie set by the server;
 * no credential is ever stored in JavaScript-readable storage. State-changing
 * requests echo the CSRF cookie in the X-CSRF-Token header.
 */

export const API_BASE = "/api/v1";

export class ApiError extends Error {
  status: number;
  code: string;
  details?: Record<string, unknown>;

  constructor(status: number, code: string, message: string, details?: Record<string, unknown>) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

type Listener = () => void;
const unauthorizedListeners = new Set<Listener>();

/** Notified when the server says the session is gone, so the app can return to the login page. */
export function onUnauthorized(listener: Listener): () => void {
  unauthorizedListeners.add(listener);
  return () => unauthorizedListeners.delete(listener);
}

export function readCookie(name: string): string | null {
  for (const part of document.cookie.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return decodeURIComponent(rest.join("="));
  }
  return null;
}

function csrfHeaders(method: string): Record<string, string> {
  if (method === "GET" || method === "HEAD") return {};
  const token = readCookie("sl_csrf");
  return token ? { "X-CSRF-Token": token } : {};
}

async function toError(response: Response): Promise<ApiError> {
  let code = "http_error";
  let message = `Request failed (${response.status})`;
  let details: Record<string, unknown> | undefined;
  try {
    const body = await response.json();
    if (body?.error) {
      code = body.error.code ?? code;
      message = body.error.message ?? message;
      details = body.error.details;
    }
  } catch {
    /* not JSON */
  }
  return new ApiError(response.status, code, message, details);
}

export type Query = Record<string, string | number | boolean | string[] | null | undefined>;

export function buildQuery(params?: Query): string {
  if (!params) return "";
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "") continue;
    if (Array.isArray(value)) value.forEach((v) => search.append(key, v));
    else search.set(key, String(value));
  }
  const text = search.toString();
  return text ? `?${text}` : "";
}

export async function request<T>(method: string, path: string, body?: unknown, params?: Query): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json", ...csrfHeaders(method) };
  let payload: BodyInit | undefined;
  if (body instanceof FormData) payload = body;
  else if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(body);
  }
  const response = await fetch(`${API_BASE}${path}${buildQuery(params)}`, {
    method,
    headers,
    body: payload,
    credentials: "same-origin",
  });
  if (!response.ok) {
    const error = await toError(response);
    if (response.status === 401 && !path.startsWith("/auth/login") && !path.startsWith("/auth/bootstrap")) {
      unauthorizedListeners.forEach((listener) => listener());
    }
    throw error;
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

export const api = {
  get: <T>(path: string, params?: Query) => request<T>("GET", path, undefined, params),
  post: <T>(path: string, body?: unknown) => request<T>("POST", path, body),
  patch: <T>(path: string, body?: unknown) => request<T>("PATCH", path, body),
  del: <T>(path: string) => request<T>("DELETE", path),
};

/** Multipart upload with progress reporting (fetch cannot report upload progress). */
export function uploadWithProgress<T>(path: string, form: FormData, onProgress: (fraction: number) => void): Promise<T> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", `${API_BASE}${path}`);
    xhr.withCredentials = true;
    const token = readCookie("sl_csrf");
    if (token) xhr.setRequestHeader("X-CSRF-Token", token);
    xhr.upload.onprogress = (event) => {
      if (event.lengthComputable) onProgress(event.loaded / event.total);
    };
    xhr.onload = () => {
      let body: unknown = null;
      try {
        body = JSON.parse(xhr.responseText);
      } catch {
        /* not JSON */
      }
      if (xhr.status >= 200 && xhr.status < 300) resolve(body as T);
      else {
        const err = (body as { error?: { code?: string; message?: string } } | null)?.error;
        if (xhr.status === 401) unauthorizedListeners.forEach((listener) => listener());
        reject(new ApiError(xhr.status, err?.code ?? "http_error", err?.message ?? `Upload failed (${xhr.status})`));
      }
    };
    xhr.onerror = () => reject(new ApiError(0, "network_error", "The upload could not reach the server"));
    xhr.send(form);
  });
}

export function reportUrl(projectId: string, scanId: string, format: string): string {
  return `${API_BASE}/projects/${projectId}/scans/${scanId}/report?format=${encodeURIComponent(format)}`;
}
