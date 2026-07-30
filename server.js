import express from "express";
import multer from "multer";
import crypto from "node:crypto";

const app = express();
const PORT = Number(process.env.PORT || 10000);
const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || "";
const CHAT_ID = process.env.TELEGRAM_CHAT_ID || "";
const THREAD_ID = process.env.TELEGRAM_MESSAGE_THREAD_ID || "";
const PRIMARY_ORIGIN = (process.env.ALLOWED_ORIGIN || "https://rpc-order-website.onrender.com").replace(/\/$/, "");
const SUPABASE_URL_RAW = String(process.env.SUPABASE_URL || "").trim();

function normalizeSupabaseUrl(value) {
  if (!value) return "";

  let normalized = value.replace(/\/+$/, "");

  // Supabase may show either the Project URL or the full Data API URL.
  // The request helper below adds /rest/v1 itself, so strip it here when present.
  normalized = normalized.replace(/\/rest\/v1$/i, "");

  try {
    const parsed = new URL(normalized);
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") return "";
    return parsed.toString().replace(/\/$/, "");
  } catch {
    return "";
  }
}

const SUPABASE_URL = normalizeSupabaseUrl(SUPABASE_URL_RAW);
const SUPABASE_SECRET_KEY = process.env.SUPABASE_SECRET_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY || "";
const REVIEWS_AUTO_APPROVE = String(process.env.REVIEWS_AUTO_APPROVE || "true").toLowerCase() === "true";
const TURNSTILE_SITE_KEY = String(process.env.TURNSTILE_SITE_KEY || "").trim();
const TURNSTILE_SECRET_KEY = String(process.env.TURNSTILE_SECRET_KEY || "").trim();
const TURNSTILE_REQUIRED = String(process.env.TURNSTILE_REQUIRED || "true").toLowerCase() !== "false";

const allowedOrigins = new Set([
  PRIMARY_ORIGIN,
  "http://localhost:3000",
  "http://127.0.0.1:3000",
  "http://localhost:5500",
  "http://127.0.0.1:5500"
]);

const rateLimits = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [key, value] of rateLimits.entries()) {
    if (now - value.startedAt > 24 * 60 * 60 * 1000) rateLimits.delete(key);
  }
}, 60 * 60 * 1000).unref();
const MAX_FILE_BYTES = 10 * 1024 * 1024;
const MAX_TOTAL_BYTES = 30 * 1024 * 1024;
const ALLOWED_EXTENSIONS = new Set([
  ".png", ".jpg", ".jpeg", ".webp", ".gif", ".pdf", ".zip", ".rar", ".7z",
  ".mp4", ".mov", ".unitypackage", ".blend", ".fbx", ".obj"
]);

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    files: 5,
    fileSize: MAX_FILE_BYTES,
    fields: 24,
    fieldSize: 20_000
  },
  fileFilter(_req, file, callback) {
    const extension = file.originalname.toLowerCase().match(/\.[a-z0-9]+$/)?.[0] || "";
    if (!ALLOWED_EXTENSIONS.has(extension)) {
      return callback(new Error("FILE_TYPE_NOT_ALLOWED"));
    }
    callback(null, true);
  }
});

app.disable("x-powered-by");
app.use(express.json({ limit: "80kb" }));
app.use(express.urlencoded({ extended: false, limit: "80kb" }));

app.use((req, res, next) => {
  const origin = String(req.headers.origin || "").replace(/\/$/, "");
  if (origin && allowedOrigins.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");

  if (req.method === "OPTIONS") {
    if (origin && !allowedOrigins.has(origin)) return res.status(403).json({ ok: false, error: "Origin запрещён" });
    return res.sendStatus(204);
  }
  next();
});

function getIp(req) {
  return String(req.headers["x-forwarded-for"] || req.socket.remoteAddress || "unknown").split(",")[0].trim();
}

function allowRate(key, max, windowMs) {
  const now = Date.now();
  const current = rateLimits.get(key);
  if (!current || now - current.startedAt > windowMs) {
    rateLimits.set(key, { startedAt: now, count: 1 });
    return true;
  }
  if (current.count >= max) return false;
  current.count += 1;
  return true;
}

function requireOrigin(req, res, next) {
  const origin = String(req.headers.origin || "").replace(/\/$/, "");
  if (!origin || !allowedOrigins.has(origin)) return res.status(403).json({ ok: false, error: "Origin запрещён" });
  next();
}

function allowPublicRead(req, res, next) {
  const origin = String(req.headers.origin || "").replace(/\/$/, "");
  if (origin && !allowedOrigins.has(origin)) return res.status(403).json({ ok: false, error: "Origin запрещён" });
  next();
}

function clean(value, maxLength) {
  return String(value ?? "")
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "")
    .replace(/[<>]/g, "")
    .trim()
    .slice(0, maxLength);
}

function requestLanguage(req) {
  return clean(req.body?.language, 5) === "en" ? "en" : "ru";
}

function localized(req, ru, en) {
  return requestLanguage(req) === "en" ? en : ru;
}

function validTelegram(value) {
  return /^@[A-Za-z0-9_]{5,32}$/.test(clean(value, 80));
}

function validFormTiming(value) {
  const startedAt = Number(value);
  if (!Number.isFinite(startedAt)) return false;
  const elapsed = Date.now() - startedAt;
  return elapsed >= 1200 && elapsed <= 6 * 60 * 60 * 1000;
}

function turnstileConfigured() {
  return Boolean(TURNSTILE_SITE_KEY && TURNSTILE_SECRET_KEY);
}

async function verifyTurnstile(token, ip) {
  if (!TURNSTILE_REQUIRED) return true;
  if (!turnstileConfigured()) throw new Error("TURNSTILE_NOT_CONFIGURED");
  const form = new URLSearchParams();
  form.set("secret", TURNSTILE_SECRET_KEY);
  form.set("response", clean(token, 4096));
  if (ip && ip !== "unknown") form.set("remoteip", ip);
  const response = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form,
    signal: AbortSignal.timeout(12_000)
  });
  const result = await response.json().catch(() => ({}));
  return Boolean(response.ok && result.success);
}

function fileMatchesSignature(file) {
  const name = clean(file.originalname, 180).toLowerCase();
  const extension = name.match(/\.[a-z0-9]+$/)?.[0] || "";
  const bytes = file.buffer;
  const ascii = bytes.subarray(0, 32).toString("ascii");
  const starts = (...values) => values.every((value, index) => bytes[index] === value);
  if (extension === ".png") return starts(0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a);
  if ([".jpg",".jpeg"].includes(extension)) return starts(0xff,0xd8,0xff);
  if (extension === ".gif") return ascii.startsWith("GIF87a") || ascii.startsWith("GIF89a");
  if (extension === ".webp") return ascii.startsWith("RIFF") && ascii.slice(8,12) === "WEBP";
  if (extension === ".pdf") return ascii.startsWith("%PDF-");
  if ([".zip",".unitypackage"].includes(extension)) return starts(0x50,0x4b) || starts(0x1f,0x8b);
  if (extension === ".rar") return ascii.startsWith("Rar!");
  if (extension === ".7z") return starts(0x37,0x7a,0xbc,0xaf,0x27,0x1c);
  if ([".mp4",".mov"].includes(extension)) return ascii.includes("ftyp");
  if (extension === ".blend") return ascii.startsWith("BLENDER");
  if (extension === ".fbx") return ascii.startsWith("Kaydara FBX Binary") || !bytes.includes(0);
  if (extension === ".obj") return !bytes.includes(0);
  return false;
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

function normalizeVisitorId(value) {
  const id = clean(value, 128);
  return /^[a-zA-Z0-9:_-]{10,128}$/.test(id) ? id : "";
}

function databaseConfigured() {
  return Boolean(SUPABASE_URL && SUPABASE_SECRET_KEY);
}

async function supabaseRequest(path, options = {}) {
  if (!databaseConfigured()) throw new Error("DATABASE_NOT_CONFIGURED");

  // New Supabase keys (sb_secret_...) are opaque API keys, not JWTs.
  // They must be sent only in the apikey header. Legacy service_role keys
  // are JWTs, so Authorization: Bearer remains valid for those keys.
  const authHeaders = {
    apikey: SUPABASE_SECRET_KEY,
    "Content-Type": "application/json"
  };

  if (!SUPABASE_SECRET_KEY.startsWith("sb_secret_")) {
    authHeaders.Authorization = `Bearer ${SUPABASE_SECRET_KEY}`;
  }

  const cleanPath = String(path || "").replace(/^\/+/, "");
  const requestUrl = new URL(`rest/v1/${cleanPath}`, `${SUPABASE_URL}/`).toString();

  const response = await fetch(requestUrl, {
    ...options,
    headers: {
      ...authHeaders,
      ...(options.headers || {})
    },
    signal: AbortSignal.timeout(15_000)
  });

  const raw = await response.text();
  let result = {};
  try {
    result = raw ? JSON.parse(raw) : {};
  } catch {
    result = { message: raw };
  }

  if (!response.ok) {
    console.error("Supabase error:", {
      status: response.status,
      path,
      code: result?.code,
      message: result?.message,
      details: result?.details,
      hint: result?.hint
    });
    throw new Error("DATABASE_REQUEST_FAILED");
  }

  return result;
}

function normalizeStats(result) {
  const row = Array.isArray(result) ? result[0] || {} : result || {};
  return {
    totalVisitors: Number(row.total_visitors || 0),
    totalViews: Number(row.total_views || 0),
    onlineUsers: Number(row.online_users || 0),
    approvedReviews: Number(row.approved_reviews || 0)
  };
}

async function getStats() {
  const result = await supabaseRequest("rpc/get_site_stats", {
    method: "POST",
    body: "{}"
  });
  return normalizeStats(result);
}

async function sendTelegramMessage(text) {
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
    signal: AbortSignal.timeout(20_000)
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok || !result.ok) {
    console.error("Telegram sendMessage error:", result);
    throw new Error("TELEGRAM_SEND_FAILED");
  }
}

async function sendTelegramFile(file, id, index, total) {
  const form = new FormData();
  form.append("chat_id", CHAT_ID);
  if (THREAD_ID) form.append("message_thread_id", THREAD_ID);
  form.append("caption", `${id} · файл ${index + 1}/${total}\n${clean(file.originalname, 180)}`);
  form.append("document", new Blob([file.buffer], { type: file.mimetype || "application/octet-stream" }), clean(file.originalname, 180) || `file-${index + 1}`);

  const response = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendDocument`, {
    method: "POST",
    body: form,
    signal: AbortSignal.timeout(45_000)
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok || !result.ok) {
    console.error("Telegram sendDocument error:", result);
    throw new Error("TELEGRAM_FILE_SEND_FAILED");
  }
}

app.get("/", (_req, res) => {
  res.json({
    ok: true,
    service: "RPC Orders API",
    endpoints: ["/health", "/api/public-config", "/api/tickets", "/api/stats", "/api/visit", "/api/presence", "/api/reviews"]
  });
});

app.get("/api/public-config", allowPublicRead, (_req, res) => {
  res.json({
    ok: true,
    turnstileRequired: TURNSTILE_REQUIRED,
    turnstileConfigured: turnstileConfigured(),
    turnstileSiteKey: TURNSTILE_SITE_KEY || null
  });
});

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    configured: Boolean(BOT_TOKEN && CHAT_ID),
    databaseConfigured: databaseConfigured(),
    databaseUrlValid: Boolean(SUPABASE_URL),
    databaseHost: SUPABASE_URL ? new URL(SUPABASE_URL).host : null,
    reviewsAutoApprove: REVIEWS_AUTO_APPROVE,
    turnstileRequired: TURNSTILE_REQUIRED,
    turnstileConfigured: turnstileConfigured()
  });
});

app.get("/api/stats", allowPublicRead, async (_req, res) => {
  try {
    res.json({ ok: true, ...(await getStats()) });
  } catch (error) {
    console.error(error);
    res.status(503).json({ ok: false, error: "Статистика временно недоступна." });
  }
});

app.post("/api/visit", requireOrigin, async (req, res) => {
  const visitorId = normalizeVisitorId(req.body?.visitorId);
  if (!visitorId) return res.status(400).json({ ok: false, error: "Некорректный идентификатор посетителя." });
  try {
    const result = await supabaseRequest("rpc/register_site_visit", {
      method: "POST",
      body: JSON.stringify({ p_visitor_id: visitorId })
    });
    res.json({ ok: true, ...normalizeStats(result) });
  } catch (error) {
    console.error(error);
    res.status(503).json({ ok: false, error: "Не удалось зарегистрировать посещение." });
  }
});

app.post("/api/presence", requireOrigin, async (req, res) => {
  const visitorId = normalizeVisitorId(req.body?.visitorId);
  if (!visitorId) return res.status(400).json({ ok: false, error: "Некорректный идентификатор посетителя." });
  try {
    const result = await supabaseRequest("rpc/touch_site_visitor", {
      method: "POST",
      body: JSON.stringify({ p_visitor_id: visitorId })
    });
    res.json({ ok: true, ...normalizeStats(result) });
  } catch (error) {
    console.error(error);
    res.status(503).json({ ok: false, error: "Не удалось обновить присутствие." });
  }
});

app.get("/api/reviews", allowPublicRead, async (_req, res) => {
  try {
    const reviews = await supabaseRequest("reviews?approved=eq.true&select=id,name,project_type,rating,body,created_at&order=created_at.desc&limit=30", {
      method: "GET"
    });
    res.json({ ok: true, reviews, count: reviews.length });
  } catch (error) {
    console.error(error);
    res.status(503).json({ ok: false, error: "Отзывы временно недоступны." });
  }
});

app.post("/api/reviews", requireOrigin, async (req, res) => {
  const ip = getIp(req);
  if (!allowRate(`review:${ip}`, 2, 24 * 60 * 60 * 1000)) {
    return res.status(429).json({ ok: false, error: localized(req, "С этого адреса уже отправлено слишком много отзывов.", "Too many reviews were submitted from this address.") });
  }
  if (clean(req.body?.website, 100)) return res.json({ ok: true, published: false });
  if (!validFormTiming(req.body?.formStartedAt)) {
    return res.status(400).json({ ok: false, error: localized(req, "Форма отправлена слишком быстро или устарела. Обновите страницу.", "The form was submitted too quickly or has expired. Refresh the page.") });
  }
  try {
    if (!(await verifyTurnstile(req.body?.turnstileToken, ip))) {
      return res.status(403).json({ ok: false, error: localized(req, "Проверка безопасности не пройдена.", "Security verification failed.") });
    }
  } catch (error) {
    console.error(error);
    return res.status(503).json({ ok: false, error: localized(req, "Защита формы временно недоступна.", "Form protection is temporarily unavailable.") });
  }

  const name = clean(req.body?.name, 80);
  const projectType = clean(req.body?.projectType, 40);
  const rating = Number(req.body?.rating);
  const body = clean(req.body?.body, 1200);
  if (!name || !projectType || !Number.isInteger(rating) || rating < 1 || rating > 5 || body.length < 20) {
    return res.status(400).json({ ok: false, error: localized(req, "Проверьте поля отзыва.", "Check the review fields.") });
  }

  try {
    const inserted = await supabaseRequest("reviews", {
      method: "POST",
      headers: { Prefer: "return=representation" },
      body: JSON.stringify({
        name,
        project_type: projectType,
        rating,
        body,
        approved: REVIEWS_AUTO_APPROVE
      })
    });
    res.json({ ok: true, published: REVIEWS_AUTO_APPROVE, reviewId: inserted?.[0]?.id || null });
  } catch (error) {
    console.error(error);
    res.status(503).json({ ok: false, error: localized(req, "Не удалось сохранить отзыв.", "Could not save the review.") });
  }
});

app.post("/api/tickets", requireOrigin, upload.array("files", 5), async (req, res) => {
  const ip = getIp(req);
  if (!allowRate(`ticket:${ip}`, 3, 15 * 60 * 1000)) {
    return res.status(429).json({ ok: false, error: localized(req, "Слишком много заявок. Попробуйте позже.", "Too many requests. Try again later.") });
  }

  try {
    if (clean(req.body?.website, 100)) return res.json({ ok: true });
    if (!validFormTiming(req.body?.formStartedAt)) {
      return res.status(400).json({ ok: false, error: localized(req, "Форма отправлена слишком быстро или устарела. Обновите страницу.", "The form was submitted too quickly or has expired. Refresh the page.") });
    }
    if (!(await verifyTurnstile(req.body?.turnstileToken, ip))) {
      return res.status(403).json({ ok: false, error: localized(req, "Проверка безопасности не пройдена.", "Security verification failed.") });
    }

    const category = clean(req.body?.category, 40);
    const clientName = clean(req.body?.clientName, 80);
    const clientTelegram = clean(req.body?.clientTelegram, 80);
    const budget = clean(req.body?.budget, 100) || "не указан";
    const description = clean(req.body?.description, 2000);
    const source = clean(req.body?.source, 300);
    const agreement = req.body?.agreement === true || String(req.body?.agreement).toLowerCase() === "true" || req.body?.agreement === "on";
    const files = Array.isArray(req.files) ? req.files : [];
    const totalBytes = files.reduce((sum, file) => sum + file.size, 0);

    if (totalBytes > MAX_TOTAL_BYTES) return res.status(413).json({ ok: false, error: localized(req, "Суммарный размер файлов превышает 30 МБ.", "The total file size exceeds 30 MB.") });
    const invalidFile = files.find(file => !fileMatchesSignature(file));
    if (invalidFile) return res.status(415).json({ ok: false, error: localized(req, `Файл «${clean(invalidFile.originalname, 120)}» не прошёл проверку формата.`, `The file “${clean(invalidFile.originalname, 120)}” failed format validation.`) });
    if (!category || !clientName || !validTelegram(clientTelegram) || description.length < 20 || !agreement) {
      return res.status(400).json({ ok: false, error: localized(req, "Проверьте обязательные поля, Telegram и согласие с правилами.", "Check the required fields, Telegram username, and rules agreement.") });
    }

    const id = ticketId();
    const fileSummary = files.length
      ? files.map((file, index) => `${index + 1}. ${clean(file.originalname, 120)} (${(file.size / 1024 / 1024).toFixed(1)} МБ)`).join("\n")
      : "нет";

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
      `Файлы (${files.length}):`,
      fileSummary,
      "",
      "С правилами согласен(-на): Да",
      source ? `Источник: ${source}` : ""
    ].filter(Boolean).join("\n");

    await sendTelegramMessage(text);

    let filesSent = 0;
    const failedFiles = [];
    for (let index = 0; index < files.length; index += 1) {
      try {
        await sendTelegramFile(files[index], id, index, files.length);
        filesSent += 1;
      } catch (error) {
        console.error(error);
        failedFiles.push(files[index].originalname);
      }
    }

    res.json({ ok: true, ticketId: id, filesSent, failedFiles });
  } catch (error) {
    console.error(error);
    const message = error?.message === "SERVER_NOT_CONFIGURED"
      ? localized(req, "Сервер Telegram ещё не настроен.", "The Telegram server is not configured yet.")
      : error?.message === "TURNSTILE_NOT_CONFIGURED"
        ? localized(req, "Cloudflare Turnstile не настроен на сервере.", "Cloudflare Turnstile is not configured on the server.")
        : localized(req, "Не удалось отправить заявку.", "Could not send the request.");
    res.status(500).json({ ok: false, error: message });
  }
});

app.use((error, _req, res, _next) => {
  console.error(error);
  if (error instanceof multer.MulterError) {
    const message = error.code === "LIMIT_FILE_SIZE"
      ? "Один из файлов больше 10 МБ."
      : error.code === "LIMIT_FILE_COUNT"
        ? "Можно прикрепить не более 5 файлов."
        : "Не удалось обработать файлы.";
    return res.status(413).json({ ok: false, error: message });
  }
  if (error?.message === "FILE_TYPE_NOT_ALLOWED") {
    return res.status(415).json({ ok: false, error: "Этот тип файла не разрешён." });
  }
  res.status(500).json({ ok: false, error: "Внутренняя ошибка сервера." });
});

app.use((_req, res) => res.status(404).json({ ok: false, error: "Not found" }));

app.listen(PORT, "0.0.0.0", () => {
  console.log(`RPC API listening on 0.0.0.0:${PORT}`);
});
