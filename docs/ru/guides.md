# Гайд по настройке и подключению клиентов

Пошаговая инструкция по запуску JustNewMCP, публикации через HTTPS и подключению к Google Gemini и OpenAI ChatGPT.

## 1. Локальный конфиг

1. Установите зависимости под Bun 1.4 или выше:

   ```bash
   bun install
   ```

2. Скопируйте `config.example.json` в `config.json` и заполните ключевые поля:
   - `publicUrl`: публичный HTTPS-адрес туннеля или обратного прокси без завершающего слеша.
   - `allowedRoots`: абсолютные пути к директориям, в которых разрешено работать агенту.
   - `oauth.clientId` и `oauth.clientSecret`: идентификатор клиента и случайный секрет длиной от 32 байт.
   - `oauth.inMemoryTokens`: по умолчанию `false`, поэтому SHA-256 хэши токенов сохраняются между перезапусками сервера в `~/.justnewmcp/oauth-tokens-<hash>.json` с правами `0600` на POSIX. Поставьте `true` или передайте `JUSTNEWMCP_IN_MEMORY_TOKENS=true`, чтобы хранить токены строго в оперативной памяти.
   - `oauth.tokenStorePath`: опциональный путь к файлу хэшей вне `allowedRoots`, также задаётся через `JUSTNEWMCP_TOKEN_STORE_PATH`.

3. Запустите сервер:

   Linux или macOS:

   ```bash
   JUSTNEWMCP_CONFIG=./config.json bun run start
   ```

   Windows PowerShell:

   ```powershell
   $env:JUSTNEWMCP_CONFIG = "./config.json"
   bun run start
   ```

При старте сервер записывает одноразовый код подтверждения в `~/.justnewmcp/approval-code-<port>-<pid>` с правами `0600`. В консоль выводится только путь к файлу, сам код в stdout не попадает.

## 2. Публикация по HTTPS через Cloudflare Tunnel

Для быстрого запуска без проброса портов:

```bash
cloudflared tunnel --url http://127.0.0.1:8787
```

Скопируйте выданный адрес `https://*.trycloudflare.com` в `publicUrl` внутри `config.json`, перезапустите сервер и откройте адрес в браузере, чтобы увидеть стартовую страницу.

Оставьте `trustedProxies` равным `["127.0.0.1", "::1"]`, если `cloudflared` работает на той же машине: так rate limit будет определять реальный IP клиента по заголовку `CF-Connecting-IP`.

## 3. Подключение к Google Gemini

В `DEFAULT_ALLOWED_REDIRECT_URIS` уже добавлены `https://gemini.google.com/`, `https://aistudio.google.com/` и `https://oauth-redirect.googleusercontent.com/`.

1. Добавьте удалённый MCP-сервер в Gemini с адресом `https://<ваш-publicUrl>/mcp`.
2. Укажите свои `oauth.clientId` и `oauth.clientSecret` из `config.json`.
3. В открывшемся окне авторизации введите текущий код из `~/.justnewmcp/approval-code-<port>-<pid>`.
4. После входа код сразу сменится на новый, а хэши access и refresh токенов сохранятся на диске при `inMemoryTokens: false`.

## 4. Подключение к OpenAI ChatGPT

В `DEFAULT_ALLOWED_REDIRECT_URIS` включены `https://chatgpt.com/` и `https://platform.openai.com/`, а метаданные `/.well-known/oauth-authorization-server` объявляют поддержку RFC 9207 через `authorization_response_iss_parameter_supported: true` и добавляют параметр `iss` к каждому редиректу авторизации. Благодаря этому ChatGPT использует стабильный callback `https://chatgpt.com/connector_platform_oauth_redirect`, а также резервный `https://chatgpt.com/connector/oauth/<callback_id>`.

1. В настройках MCP-коннектора ChatGPT укажите URL `https://<ваш-publicUrl>/mcp`.
2. Выберите авторизацию OAuth и задайте свои `oauth.clientId` и `oauth.clientSecret`.
3. Подтвердите вход одноразовым кодом из локального файла.

Источник требований: [OpenAI MCP Authentication Guide](https://developers.openai.com/plugins/build/auth).

## 5. Советы по безопасности

- Держите `allowEnvReading` и `allowShell` выключенными, пока они реально не понадобятся.
- В `allowedCommands` ограничивайте подкоманды и запрещайте опасные флаги через `deniedArgs`, например `-c` и `--exec-path*` для `git`.
- Включайте `oauth.inMemoryTokens: true` на временных или общих машинах, чтобы любой перезапуск сервера сбрасывал активные OAuth-сессии.
- Не кладите `oauth.tokenStorePath` внутрь `allowedRoots`: сервер заблокирует такой запуск на старте.
