// billy wonder - ledger api (login + per user data)
import { getStore } from "@netlify/blobs";
import { scrypt, randomBytes, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";

const scryptAsync = promisify(scrypt);
const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json" } });

const isDate = (d) => typeof d === "string" && /^\d{4}-\d{2}-\d{2}$/.test(d);
const num = (v) => (typeof v === "number" && Number.isFinite(v) ? v : null);
const SESSION_MS = 90 * 24 * 3600 * 1000;

const users = () => getStore({ name: "users", consistency: "strong" });
const sessions = () => getStore({ name: "sessions", consistency: "strong" });
const ledger = () => getStore({ name: "ledger", consistency: "strong" });

async function hashPw(password, salt) {
  return (await scryptAsync(password, salt, 64)).toString("hex");
}

async function auth(req) {
  const m = /^Bearer ([a-f0-9]{64})$/.exec(req.headers.get("authorization") || "");
  if (!m) return null;
  const s = await sessions().get("tok:" + m[1], { type: "json" });
  if (!s || s.exp < Date.now()) return null;
  return { username: s.u, token: m[1] };
}

async function handleAuth(req) {
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);
  const b = await req.json().catch(() => ({}));

  if (b.action === "logout") {
    const a = await auth(req);
    if (a) await sessions().delete("tok:" + a.token);
    return json({ ok: true });
  }

  const username = String(b.username || "").trim().toLowerCase();
  const password = String(b.password || "");
  if (!/^[a-z0-9_]{3,20}$/.test(username))
    return json({ error: "Username: 3-20 letters, numbers or _ only" }, 400);
  if (password.length < 6 || password.length > 100)
    return json({ error: "Password must be at least 6 characters" }, 400);

  const key = "user:" + username;
  if (b.action === "register") {
    if (await users().get(key)) return json({ error: "Username already taken" }, 409);
    const salt = randomBytes(16).toString("hex");
    await users().setJSON(key, { username, salt, hash: await hashPw(password, salt), created: Date.now() });
  } else if (b.action === "login") {
    const u = await users().get(key, { type: "json" });
    const ok = u && timingSafeEqual(Buffer.from(await hashPw(password, u.salt), "hex"), Buffer.from(u.hash, "hex"));
    if (!ok) return json({ error: "Wrong username or password" }, 401);
  } else return json({ error: "Bad request" }, 400);

  const token = randomBytes(32).toString("hex");
  await sessions().setJSON("tok:" + token, { u: username, exp: Date.now() + SESSION_MS });
  return json({ token, username });
}

async function handleLedger(req) {
  const a = await auth(req);
  if (!a) return json({ error: "Please log in" }, 401);
  const store = ledger();
  const url = new URL(req.url);
  const dayKey = (date) => `${a.username}/day:${date}`;

  if (req.method === "GET") {
    const date = url.searchParams.get("date");
    if (!isDate(date)) return json({ error: "Bad date" }, 400);
    return json({ records: (await store.get(dayKey(date), { type: "json" })) || [] });
  }

  const body = await req.json().catch(() => ({}));

  if (req.method === "POST") {
    const r = body.record || {};
    const buy = num(r.buy), sell = num(r.sell), qty = num(r.qty);
    if (!isDate(r.date) || typeof r.id !== "string" || typeof r.item !== "string" || !r.item.trim()
        || buy === null || sell === null || qty === null || buy < 0 || sell < 0 || qty < 1)
      return json({ error: "Invalid entry" }, 400);
    const rec = {
      id: r.id.slice(0, 60), date: r.date, item: r.item.trim().slice(0, 70),
      buy, sell, qty: Math.floor(qty), note: String(r.note || "").slice(0, 120),
      created: num(r.created) ?? Date.now(),
    };
    const records = (await store.get(dayKey(rec.date), { type: "json" })) || [];
    if (!records.some((x) => x.id === rec.id)) records.push(rec);
    await store.setJSON(dayKey(rec.date), records);
    return json({ records });
  }

  if (req.method === "DELETE") {
    if (!isDate(body.date)) return json({ error: "Bad date" }, 400);
    const records = ((await store.get(dayKey(body.date), { type: "json" })) || []).filter((x) => x.id !== body.id);
    await store.setJSON(dayKey(body.date), records);
    return json({ records });
  }

  return json({ error: "Method not allowed" }, 405);
}

export default async (req) => {
  try {
    const path = new URL(req.url).pathname;
    return path.startsWith("/api/auth") ? await handleAuth(req) : await handleLedger(req);
  } catch (e) {
    return json({ error: "Server error: " + e.message }, 500);
  }
};

export const config = { path: ["/api/ledger", "/api/auth"] };
