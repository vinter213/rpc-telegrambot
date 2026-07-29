RPC ORDER BOT API

Этот проект — защищённый сервер между сайтом заказов и Telegram-ботом.
Токен бота нельзя добавлять в index.html или app.js.

Файлы загружаются в отдельный GitHub-репозиторий без папок:
- package.json
- server.js
- render.yaml
- .gitignore
- README.txt

Рекомендуемое имя репозитория:
rpc-order-bot-api

НАСТРОЙКА RENDER
1. Render → New → Web Service.
2. Подключите репозиторий rpc-order-bot-api.
3. Name: rpc-order-bot-vinter294
4. Runtime: Node
5. Build Command: npm install
6. Start Command: npm start
7. Health Check Path: /health

ENVIRONMENT VARIABLES
TELEGRAM_BOT_TOKEN = токен от BotFather
TELEGRAM_CHAT_ID = числовой ID личного чата или группы
ALLOWED_ORIGIN = https://rpc-order-website.onrender.com
TELEGRAM_MESSAGE_THREAD_ID = оставить пустым, если бот пишет не в тему форума

ВАЖНО
- Сначала отправьте боту /start.
- Не публикуйте токен в GitHub.
- После деплоя откройте /health. Должно быть: {"ok":true,"configured":true}
- Если адрес Web Service отличается от https://rpc-order-bot-vinter294.onrender.com,
  замените TICKET_API_URL в app.js сайта заказов.
