"use client";

/**
 * Browser API client for the admin BFF. The session lives in an HttpOnly cookie that
 * JavaScript cannot read; mutations carry the CSRF token obtained from /auth/me.
 * Responses are JSON and are always rendered as text (React escapes), never as HTML.
 */
import { useCallback, useEffect, useRef, useState } from "react";

let csrf: string | null = null;

export function setCsrf(token: string | null) {
  csrf = token;
}

export class ApiError extends Error {
  constructor(public status: number, message: string, public details?: unknown) {
    super(message);
  }
}

export async function api<T = unknown>(
  path: string,
  init: RequestInit & { json?: unknown } = {},
): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("X-Request-ID", crypto.randomUUID().replaceAll("-", ""));
  if (init.json !== undefined) headers.set("Content-Type", "application/json");
  if (init.method && init.method !== "GET" && csrf) headers.set("X-CSRF-Token", csrf);
  const res = await fetch(`/api/admin${path}`, {
    ...init,
    headers,
    body: init.json !== undefined ? JSON.stringify(init.json) : init.body,
    credentials: "same-origin",
    cache: "no-store",
  });
  if (res.status === 401 && typeof window !== "undefined" && !path.startsWith("/auth/")) {
    window.location.href = "/login";
  }
  const body = res.headers.get("content-type")?.includes("json") ? await res.json() : null;
  if (!res.ok) {
    const err = body?.error ?? {};
    throw new ApiError(res.status, err.message ?? `Request failed (${res.status})`, err.details);
  }
  return body as T;
}

export function useApi<T>(path: string | null, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(Boolean(path));
  const seq = useRef(0);
  const reload = useCallback(async () => {
    if (!path) return;
    const id = ++seq.current;
    setLoading(true);
    try {
      const result = await api<T>(path);
      if (id === seq.current) {
        setData(result);
        setError(null);
      }
    } catch (e) {
      if (id === seq.current) setError(e instanceof Error ? e.message : "Request failed");
    } finally {
      if (id === seq.current) setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [path, ...deps]);
  useEffect(() => {
    void reload();
  }, [reload]);
  return { data, error, loading, reload, setData };
}

/** Server-Sent Events from the admin gateway; calls onEvent for matching event names. */
export function useRealtime(streams: string, names: string[], onEvent: () => void) {
  const handler = useRef(onEvent);
  handler.current = onEvent;
  useEffect(() => {
    const source = new EventSource(`/api/admin/v1/admin/stream?streams=${streams}`);
    const listeners = names.map((n) => {
      const fn = () => handler.current();
      source.addEventListener(n, fn);
      return [n, fn] as const;
    });
    return () => {
      listeners.forEach(([n, fn]) => source.removeEventListener(n, fn));
      source.close();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [streams, names.join(",")]);
}

export type Page<T> = { items: T[]; total: number; limit: number; offset: number };

export type Me = {
  user_id: string;
  display_name: string;
  tenant_id: string;
  tenant_name: string | null;
  roles: string[];
  permissions: string[];
  mfa: boolean;
  csrf_token: string;
};
