/**
 * Copyright 2026 the original author or authors from the Chautari project.
 *
 * This file is part of the Chautari project, see https://github.com/lukelittle/chautari
 * for more information.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// api.js: the only module that talks to the server.

const ACTOR_KEY = "chautari.actor";

export class AuthError extends Error {
  constructor(message = "Sign in to continue") {
    super(message);
    this.name = "AuthError";
  }
}

export class ApiError extends Error {
  constructor(status, message, body) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }
}

function readCookie(name) {
  for (const part of document.cookie.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) {
      try {
        // The server uses Go's url.QueryEscape, which encodes spaces as "+".
        return decodeURIComponent(v.join("=").replace(/\+/g, " "));
      } catch {
        return "";
      }
    }
  }
  return "";
}

export function getActor() {
  let a = "";
  try {
    a = sessionStorage.getItem(ACTOR_KEY) || "";
  } catch {
    /* storage may be unavailable */
  }
  return a || readCookie("chautari_actor");
}

function setActor(a) {
  try {
    if (a) sessionStorage.setItem(ACTOR_KEY, a);
    else sessionStorage.removeItem(ACTOR_KEY);
  } catch {
    /* ignore */
  }
}

async function parse(res) {
  const ct = res.headers.get("Content-Type") || "";
  if (res.status === 204) return null;
  if (ct.includes("application/json")) {
    try {
      return await res.json();
    } catch {
      return null;
    }
  }
  return res.text();
}

// request performs an admin API call. Mutating calls carry the actor.
export async function request(method, path, body) {
  const headers = { Accept: "application/json" };
  const init = { method, headers, credentials: "same-origin" };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  if (method !== "GET" && method !== "HEAD") {
    // A custom header cross-site pages cannot send: the server's CSRF check.
    headers["X-Requested-With"] = "chautari-ui";
    const actor = getActor();
    if (actor) headers["X-Chautari-Actor"] = actor;
  }
  let res;
  try {
    res = await fetch(path, init);
  } catch {
    throw new ApiError(0, "The control plane did not answer. Is it running?");
  }
  const data = await parse(res);
  if (res.status === 401) throw new AuthError(data && data.error);
  if (!res.ok) {
    const msg = (data && data.error) || (typeof data === "string" && data.trim()) || `${res.status} ${res.statusText}`;
    throw new ApiError(res.status, msg, data);
  }
  return data;
}

export const get = (p) => request("GET", p);
export const post = (p, b) => request("POST", p, b ?? {});
export const del = (p) => request("DELETE", p);

export async function signIn(token, actor) {
  const res = await fetch("/api/session", {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token, actor }),
  });
  const data = await parse(res);
  if (!res.ok) throw new ApiError(res.status, (data && data.error) || "Sign-in failed", data);
  setActor(data.actor || actor);
  return data.actor || actor;
}

// whoAmI asks the server who the session belongs to, so a reload never
// depends on what the browser remembered.
export async function whoAmI() {
  const data = await get("/api/session");
  setActor(data.actor || "");
  return data;
}

export async function signOut() {
  setActor("");
  try {
    await fetch("/api/session", { method: "DELETE", credentials: "same-origin" });
  } catch {
    /* the cookies expire on their own */
  }
}

// Small cache for data many pages share and that changes rarely.
const cache = new Map();
export async function cached(path, ttlMs = 15000) {
  const hit = cache.get(path);
  if (hit && Date.now() - hit.t < ttlMs) return hit.p;
  const p = get(path);
  cache.set(path, { t: Date.now(), p });
  p.catch(() => cache.delete(path));
  return p;
}
export function invalidate(prefix = "") {
  for (const k of cache.keys()) if (k.startsWith(prefix)) cache.delete(k);
}
