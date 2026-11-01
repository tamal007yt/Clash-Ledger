// billy wonder - ledger api (login + per user data)
import { getStore } from "@netlify/blobs";
import { scrypt, randomBytes, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";

const billyScrypt = promisify(scrypt);
const billyJson = (billyObj, billyCode = 200) =>
  new Response(JSON.stringify(billyObj), { status: billyCode, headers: { "content-type": "application/json" } });

const billyIsDate = (billyD) => typeof billyD === "string" && /^\d{4}-\d{2}-\d{2}$/.test(billyD);
const billyNum = (billyV) => (typeof billyV === "number" && Number.isFinite(billyV) ? billyV : null);
const BILLY_SESSION_MS = 90 * 24 * 3600 * 1000;

const billyUsers = () => getStore({ name: "users", consistency: "strong" });
const billySessions = () => getStore({ name: "sessions", consistency: "strong" });
const billyLedger = () => getStore({ name: "ledger", consistency: "strong" });

async function billyHashPw(billyPw, billySalt) {
  return (await billyScrypt(billyPw, billySalt, 64)).toString("hex");
}

async function billyAuth(billyReq) {
  const billyM = /^Bearer ([a-f0-9]{64})$/.exec(billyReq.headers.get("authorization") || "");
  if (!billyM) return null;
  const billyS = await billySessions().get("tok:" + billyM[1], { type: "json" });
  if (!billyS || billyS.exp < Date.now()) return null;
  return { username: billyS.u, token: billyM[1] };
}

async function billyHandleAuth(billyReq) {
  if (billyReq.method !== "POST") return billyJson({ error: "Method not allowed" }, 405);
  const billyB = await billyReq.json().catch(() => ({}));

  if (billyB.action === "logout") {
    const billyA = await billyAuth(billyReq);
    if (billyA) await billySessions().delete("tok:" + billyA.token);
    return billyJson({ ok: true });
  }

  const billyName = String(billyB.username || "").trim().toLowerCase();
  const billyPw = String(billyB.password || "");
  if (!/^[a-z0-9_]{3,20}$/.test(billyName))
    return billyJson({ error: "Username: 3-20 letters, numbers or _ only" }, 400);
  if (billyPw.length < 6 || billyPw.length > 100)
    return billyJson({ error: "Password must be at least 6 characters" }, 400);

  const billyKey = "user:" + billyName;
  if (billyB.action === "register") {
    if (await billyUsers().get(billyKey)) return billyJson({ error: "Username already taken" }, 409);
    const billySalt = randomBytes(16).toString("hex");
    await billyUsers().setJSON(billyKey, {
      username: billyName, salt: billySalt, hash: await billyHashPw(billyPw, billySalt), created: Date.now(),
    });
  } else if (billyB.action === "login") {
    const billyU = await billyUsers().get(billyKey, { type: "json" });
    const billyOk = billyU && timingSafeEqual(
      Buffer.from(await billyHashPw(billyPw, billyU.salt), "hex"), Buffer.from(billyU.hash, "hex"));
    if (!billyOk) return billyJson({ error: "Wrong username or password" }, 401);
  } else return billyJson({ error: "Bad request" }, 400);

  const billyTok = randomBytes(32).toString("hex");
  await billySessions().setJSON("tok:" + billyTok, { u: billyName, exp: Date.now() + BILLY_SESSION_MS });
  return billyJson({ token: billyTok, username: billyName });
}

async function billyHandleLedger(billyReq) {
  const billyA = await billyAuth(billyReq);
  if (!billyA) return billyJson({ error: "Please log in" }, 401);
  const billyStore = billyLedger();
  const billyUrl = new URL(billyReq.url);
  const billyDayKey = (billyDate) => `${billyA.username}/day:${billyDate}`;

  if (billyReq.method === "GET") {
    const billyMonth = billyUrl.searchParams.get("month");
    if (billyMonth) {
      if (!/^\d{4}-\d{2}$/.test(billyMonth)) return billyJson({ error: "Bad month" }, 400);
      const billyList = await billyStore.list({ prefix: `${billyA.username}/day:${billyMonth}` });
      const billyDays = {};
      await Promise.all(billyList.blobs.map(async (billyBlob) => {
        const billyItems = (await billyStore.get(billyBlob.key, { type: "json" })) || [];
        if (!billyItems.length) return;
        const billyProfit = billyItems.reduce((billyT, billyI) => billyT + (billyI.sell - billyI.buy) * billyI.qty, 0);
        billyDays[billyBlob.key.split("day:")[1]] = { profit: Math.round(billyProfit * 100) / 100, count: billyItems.length };
      }));
      return billyJson({ days: billyDays });
    }
    const billyDate = billyUrl.searchParams.get("date");
    if (!billyIsDate(billyDate)) return billyJson({ error: "Bad date" }, 400);
    return billyJson({ records: (await billyStore.get(billyDayKey(billyDate), { type: "json" })) || [] });
  }

  const billyBody = await billyReq.json().catch(() => ({}));

  if (billyReq.method === "POST") {
    const billyR = billyBody.record || {};
    const billyBuy = billyNum(billyR.buy), billySell = billyNum(billyR.sell), billyQty = billyNum(billyR.qty);
    if (!billyIsDate(billyR.date) || typeof billyR.id !== "string" || typeof billyR.item !== "string" || !billyR.item.trim()
        || billyBuy === null || billySell === null || billyQty === null || billyBuy < 0 || billySell < 0 || billyQty < 1)
      return billyJson({ error: "Invalid entry" }, 400);
    const billyRec = {
      id: billyR.id.slice(0, 60), date: billyR.date, item: billyR.item.trim().slice(0, 70),
      buy: billyBuy, sell: billySell, qty: Math.floor(billyQty), note: String(billyR.note || "").slice(0, 120),
      created: billyNum(billyR.created) ?? Date.now(),
    };
    const billyRecords = (await billyStore.get(billyDayKey(billyRec.date), { type: "json" })) || [];
    if (!billyRecords.some((billyX) => billyX.id === billyRec.id)) billyRecords.push(billyRec);
    await billyStore.setJSON(billyDayKey(billyRec.date), billyRecords);
    return billyJson({ records: billyRecords });
  }

  if (billyReq.method === "DELETE") {
    if (!billyIsDate(billyBody.date)) return billyJson({ error: "Bad date" }, 400);
    const billyRecords = ((await billyStore.get(billyDayKey(billyBody.date), { type: "json" })) || [])
      .filter((billyX) => billyX.id !== billyBody.id);
    await billyStore.setJSON(billyDayKey(billyBody.date), billyRecords);
    return billyJson({ records: billyRecords });
  }

  return billyJson({ error: "Method not allowed" }, 405);
}

export default async (billyReq) => {
  try {
    const billyPath = new URL(billyReq.url).pathname;
    return billyPath.startsWith("/api/auth") ? await billyHandleAuth(billyReq) : await billyHandleLedger(billyReq);
  } catch (billyErr) {
    return billyJson({ error: "Server error: " + billyErr.message }, 500);
  }
};

export const config = { path: ["/api/ledger", "/api/auth"] };
