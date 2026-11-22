# Архитектура

JustNewMCP это кроссплатформенный MCP сервер на TypeScript под Bun 1.4+, рассчитанный на Linux и Windows из коробки. Сервер работает по протоколу Streamable HTTP на эндпоинте `/mcp` за авторизацией OAuth 2.1.

## Авторизация и транспорт

- **Эндпоинт.** Streamable HTTP по адресу `https://<host>/mcp` с заголовком `Mcp-Session-Id` на каждую сессию и поддержкой SSE-уведомлений `notifications/tools/list_changed`.
- **OAuth 2.1.** Встроенные эндпоинты `/.well-known/oauth-protected-resource`, `/.well-known/oauth-authorization-server`, `/oauth/authorize`, `/oauth/token` и `/oauth/revoke` с поддержкой PKCE S256, RFC 9207 `iss` для Google Gemini и OpenAI ChatGPT, stateless `Bun.CSRF` и `HashedTokenStore`, который сохраняет SHA-256 хэши токенов в файл `0600` вне `allowedRoots`, если не включён `oauth.inMemoryTokens: true`.
- **Защита от перебора.** Секреты и токены сравниваются через `crypto.timingSafeEqual`, на ошибочные запросы действует ограничение по IP с учетом доверенных прокси, а одноразовый код подтверждения пишется в локальный файл с правами `0600` на каждый инстанс вне `allowedRoots` и не попадает в stdout.

## Основные модули

1. **Рабочая область и git worktree.** `workspace_init` переключается только внутри разрешенных в конфиге корней после проверок `path.resolve` и `fs.realpath`, подгружая `AGENTS.md` или `CLAUDE.md`, `git status` с `core.fsmonitor=false` и индекс памяти. `worktree_enter` и `worktree_exit` создают, переподключают, сохраняют или удаляют изолированные worktree в `.justnewmcp/worktrees/` с отключёнными git-хуками и внешними фильтрами.
2. **Файлы и чекпоинты.** `read_file` с нумерацией строк и проверкой UTF-8, `edit_file` с проверкой предварительного чтения и уникальности фрагмента, атомарный `multi_edit`, `write_file`, `glob_files` и `grep_files` с учетом `.gitignore` и `deniedPathPatterns`. Перед каждой записью создается снимок файла в `.justnewmcp/checkpoints/` для `checkpoint_list` и `checkpoint_rewind`.
3. **Память проекта.** `memory_read`, `memory_write` и `memory_search` поверх компактного индекса `MEMORY.md` с ограниченным чтением до 25 КБ и 200 строк на старте и ссылками на тематические папки вроде `how-to-use-user-machine/INDEX.md`. Хранится либо в `<workspace>/.justnewmcp/memory/`, либо в отдельной папке `memoryDir/<нормализованный-путь-проекта>/` вроде `c--users--vaiprog--somecoolproject--<хеш>`. Запись проверяет `deniedPathPatterns`, идет синхронно через один дескриптор с `O_NOFOLLOW` и ставит параллельные `append` в очередь по пути файла.
4. **Задачи и режим плана.** Серверные инструменты `task_create`, `task_update`, `task_list` и `task_get`, а также `plan_enter` и `plan_exit`, которые программно запрещают запись до выхода из режима плана.
5. **Белый список команд, фоновые процессы и опциональный шелл.** `run_allowed_cmd` сверяет имя бинарника и аргументы `argv` с локальным конфигом и запускает процесс через `Bun.spawn` без шелла. Вывод длиннее 30 тысяч символов сохраняется в `.justnewmcp/logs/` с правами `0600`, а в ответ уходит превью на 2 тысячи символов и путь к файлу. Флаг `background: true` регистрирует фоновую задачу для `cmd_status` и `task_stop` с завершением при остановке сервера. Опциональный `run_shell` для Bash и PowerShell скрыт и выключен до явного включения `allowShell: true`.
6. **Кодовая аналитика LSP.** Модули `src/workspace/lsp.ts` и `src/workspace/lsp-protocol.ts` управляют stdio языковыми серверами с байтовым разбором UTF-8 `Content-Length`, push и pull диагностиками, фильтрацией URI по границам воркспейса, idle-остановкой и восстановлением после сбоев через `lsp_diagnostics`, `lsp_definition` и `lsp_references`.
7. **Поиск инструментов.** Модуль `src/mcp/tool-registry.ts` при `deferredTools: true` оставляет на старте базовые инструменты и `tool_search`, включает расширенные модули по запросу отдельно для каждого `Mcp-Session-Id` и отправляет `notifications/tools/list_changed` по SSE.

## Статус этапов

- **Этап 1, завершен в `main`.** OAuth 2.1, `workspace_init`, файловые инструменты с чекпоинтами, безопасная работа с `.env`, `memory_read`, `memory_write`, `memory_search`, трекер задач, режим плана, `run_allowed_cmd` с выгрузкой длинных логов и автоматизация безопасности в CI.
- **Этап 2, завершен в `main`.** Git worktree в [#12](https://github.com/VAIPROG/JustNewMCP/issues/12), фоновые процессы с `task_stop` в [#13](https://github.com/VAIPROG/JustNewMCP/issues/13), `tool_search` в [#14](https://github.com/VAIPROG/JustNewMCP/issues/14), диагностика LSP в [#15](https://github.com/VAIPROG/JustNewMCP/issues/15) и опциональный `run_shell` в [#16](https://github.com/VAIPROG/JustNewMCP/issues/16).
