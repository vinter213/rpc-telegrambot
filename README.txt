RPC API v3 — TURNSTILE + HARDENING
==================================

Загрузи все файлы из архива в корень GitHub-репозитория rpc-telegrambot с заменой старых.
Render автоматически выполнит npm install и npm start.

НОВЫЕ ПЕРЕМЕННЫЕ RENDER
-----------------------
TURNSTILE_REQUIRED=true
TURNSTILE_SITE_KEY=публичный Site Key из Cloudflare Turnstile
TURNSTILE_SECRET_KEY=секретный Secret Key из Cloudflare Turnstile

Старые переменные оставить:
TELEGRAM_BOT_TOKEN
TELEGRAM_CHAT_ID
TELEGRAM_MESSAGE_THREAD_ID (пусто для личного чата)
ALLOWED_ORIGIN=https://rpc-order-website.onrender.com
SUPABASE_URL=https://PROJECT.supabase.co
SUPABASE_SECRET_KEY=sb_secret_...
REVIEWS_AUTO_APPROVE=true
NODE_VERSION=22

НАСТРОЙКА CLOUDFLARE TURNSTILE
------------------------------
1. В Cloudflare Dashboard открой Turnstile.
2. Создай новый виджет для домена rpc-order-website.onrender.com.
3. Скопируй Site Key в TURNSTILE_SITE_KEY.
4. Скопируй Secret Key в TURNSTILE_SECRET_KEY.
5. Нажми Save, rebuild, and deploy в Render.

ПРОВЕРКА
--------
https://rpc-telegrambot.onrender.com/health

Ожидается:
"turnstileRequired": true
"turnstileConfigured": true

https://rpc-telegrambot.onrender.com/api/public-config

Публично возвращается только Site Key. Secret Key никогда не отправляется браузеру.

ДОПОЛНИТЕЛЬНАЯ ЗАЩИТА
---------------------
- серверная проверка Turnstile;
- лимит 3 тикета за 15 минут с одного IP;
- лимит 2 отзыва в сутки с одного IP;
- honeypot;
- минимальное время заполнения формы;
- проверка Telegram @username;
- расширение + сигнатура файла;
- до 5 файлов, 10 МБ каждый, 30 МБ суммарно;
- очистка управляющих символов и HTML-скобок;
- CORS только для основного сайта.
