import http from "node:http";
import crypto from "node:crypto";

const PORT = Number(process.env.PORT || 10000);
const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || "";
const CHAT_ID = process.env.TELEGRAM_CHAT_ID || "";
const THREAD_ID = process.env.TELEGRAM_MESSAGE_THREAD_ID || "";
const PRIMARY_ORIGIN = process.env.ALLOWED_ORIGIN || "https://rpc-order-website.onrender.com";

const allowedOrigins = new Set([
  PRIMARY_ORIGIN,
  "http://localhost:3000",
  "http://127.0.0.1:3000"
]);

const rateLimits = new Map();
const RATE_WINDOW_MS = 10 * 60 * 1000;
const RATE_MAX = 4;
const BODY_LIMIT = 100_000;

function json(res, status, payload, origin = "") {
  const headers = {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff"
  };
  if (origin && allowedOrigins.has(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
    headers["Vary"] = "Origin";
  }
  res.writeHead(status, headers);
  res.end(JSON.stringify(payload));
}

function getIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  return String(forwarded || req.socket.remoteAddress || "unknown").split(",")[0].trim();
}

function checkRateLimit(ip) {
  const now = Date.now();
  const current = rateLimits.get(ip);
  if (!current || now - current.startedAt > RATE_WINDOW_MS) {
    rateLimits.set(ip, { startedAt: now, count: 1 });
    return true;
  }
  if (current.count >= RATE_MAX) return false;
  current.count += 1;
  return true;
}

function clean(value, maxLength) {
  return String(value ?? "").replace(/\u0000/g, "").trim().slice(0, maxLength);
}

function categoryLabel(value) {
  return ({
    avatar: "VRChat-аватар",
    world: "VRChat-мир",
    quest: "Quest-версия",
    optimization: "Оптимизация",
    functions: "Функции / системы",
    other: "Другое"
  })[value] || value;
}

function ticketId() {
  const day = new Date().toISOString().slice(2, 10).replaceAll("-", "");
  return `RPC-${day}-${crypto.randomBytes(3).toString("hex").toUpperCase()}`;
}

async function readJson(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > BODY_LIMIT) throw new Error("BODY_TOO_LARGE");
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
}

async function sendTelegram(text) {
  if (!BOT_TOKEN || !CHAT_ID) throw new Error("SERVER_NOT_CONFIGURED");

  const payload = {
    chat_id: CHAT_ID,
    text,
    disable_web_page_preview: true
  };
  if (THREAD_ID) payload.message_thread_id = Number(THREAD_ID);

  const response = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(15_000)
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok || !result.ok) {
    console.error("Telegram API error:", result);
    throw new Error("TELEGRAM_SEND_FAILED");
  }
}

const server = http.createServer(async (req, res) => {
  const origin = String(req.headers.origin || "");
  const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);

  if (req.method === "OPTIONS") {
    if (!allowedOrigins.has(origin)) return json(res, 403, { ok: false, error: "Origin запрещён" });
    res.writeHead(204, {
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Max-Age": "86400",
      "Vary": "Origin"
    });
    return res.end();
  }

  if (req.method === "GET" && url.pathname === "/health") {
    return json(res, 200, { ok: true, configured: Boolean(BOT_TOKEN && CHAT_ID) }, origin);
  }

  if (req.method !== "POST" || url.pathname !== "/api/tickets") {
    return json(res, 404, { ok: false, error: "Not found" }, origin);
  }

  if (!allowedOrigins.has(origin)) {
    return json(res, 403, { ok: false, error: "Origin запрещён" });
  }

  const ip = getIp(req);
  if (!checkRateLimit(ip)) {
    return json(res, 429, { ok: false, error: "Слишком много заявок. Попробуйте позже." }, origin);
  }

  try {
    const body = await readJson(req);
    if (clean(body.website, 100)) return json(res, 200, { ok: true }, origin);

    const category = clean(body.category, 40);
    const clientName = clean(body.clientName, 80);
    const clientTelegram = clean(body.clientTelegram, 80);
    const budget = clean(body.budget, 100) || "не указан";
    const description = clean(body.description, 2000);
    const source = clean(body.source, 300);
    const agreement = body.agreement === true;

    if (!category || !clientName || !clientTelegram || description.length < 20 || !agreement) {
      return json(res, 400, { ok: false, error: "Проверьте обязательные поля и согласие с правилами." }, origin);
    }

    const id = ticketId();
    const text = [
      "🔥 Новый заказ RPC",
      "",
      `Номер тикета: ${id}`,
      `Категория: ${categoryLabel(category)}`,
      `Имя / ник: ${clientName}`,
      `Telegram заказчика: ${clientTelegram}`,
      `Бюджет: ${budget}`,
      "",
      "Описание:",
      description,
      "",
      "С правилами согласен(-на): Да",
      source ? `Источник: ${source}` : ""
    ].filter(Boolean).join("\n");

    await sendTelegram(text);
    return json(res, 200, { ok: true, ticketId: id }, origin);
  } catch (error) {
    console.error(error);
    const message = error?.message === "BODY_TOO_LARGE"
      ? "Слишком большой запрос."
      : error?.message === "SERVER_NOT_CONFIGURED"
        ? "Сервер ещё не настроен."
        : "Не удалось отправить заявку.";
    return json(res, error?.message === "BODY_TOO_LARGE" ? 413 : 500, { ok: false, error: message }, origin);
  }
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`RPC Order Bot API listening on 0.0.0.0:${PORT}`);
});
