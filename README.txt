RPC API 2.0 — Telegram, файлы, отзывы и общая статистика

1. Замените в GitHub старые файлы API этими файлами:
   server.js
   package.json
   render.yaml
   .gitignore
   supabase-setup.sql

2. Создайте бесплатный проект Supabase.

3. Откройте Supabase -> SQL Editor -> New query.
   Вставьте содержимое supabase-setup.sql и нажмите Run.

4. В Supabase откройте Settings -> API Keys / Connect.
   Скопируйте:
   - Project URL
   - Secret key (или старый service_role key)

5. В Render -> rpc-telegrambot -> Environment добавьте:
   SUPABASE_URL=https://ВАШ-ПРОЕКТ.supabase.co
   SUPABASE_SECRET_KEY=sb_secret_... или service_role key
   REVIEWS_AUTO_APPROVE=true

   Уже существующие переменные оставьте:
   TELEGRAM_BOT_TOKEN
   TELEGRAM_CHAT_ID
   ALLOWED_ORIGIN=https://rpc-order-website.onrender.com

6. Нажмите Save, rebuild, and deploy.

7. Проверьте:
   https://rpc-telegrambot.onrender.com/health

Ожидаемый ответ:
{
  "ok": true,
  "configured": true,
  "databaseConfigured": true,
  "reviewsAutoApprove": true
}

Файлы тикета:
- до 5 файлов;
- до 10 МБ каждый;
- до 30 МБ суммарно;
- отправляются в Telegram после текста заявки.

Отзывы:
REVIEWS_AUTO_APPROVE=true  — публикуются сразу.
REVIEWS_AUTO_APPROVE=false — сохраняются как approved=false.
Чтобы вручную опубликовать отзыв: Supabase -> Table Editor -> reviews -> approved=true.

Никогда не загружайте SUPABASE_SECRET_KEY и TELEGRAM_BOT_TOKEN в GitHub.
