# JustNewMCP

[English README](../../README.md) · [Архитектура](./architecture.md)

Удаленный MCP сервер, который превращает любую чат-модель с поддержкой MCP в локального кодинг-агента. Написан на TypeScript под Bun 1.4+ для Linux и Windows, с авторизацией OAuth 2.1 и рабочей моделью по принципам Claude Code.

## Зачем мы это делаем

Чат-клиенты уже умеют подключать MCP, но большинство локальных серверов сводятся к сырому чтению и записи файлов. В итоге модель гадает пути, переписывает файлы целиком и работает без памяти и отката. JustNewMCP собирает недостающую среду в одном локальном сервере: ограниченные рабочие корни, точечные правки с чекпоинтами, память проекта, трекер задач, git worktree, фоновые процессы, диагностику LSP и ленивую загрузку инструментов.

## Статус

Первый и второй этапы полностью завершены в `main`: 69 тестов проходят на Linux и Windows, открытых алертов Code Scanning нет.

### Уже готово в `main`

- **Авторизация OAuth 2.1.** Встроенный сервер на эндпоинтах `/.well-known/oauth-protected-resource`, `/.well-known/oauth-authorization-server`, `/oauth/authorize`, `/oauth/token` и `/oauth/revoke` с PKCE S256, stateless `Bun.CSRF`, точным сравнением callback URI, одноразовыми кодами в файле `0600` на каждый инстанс вне `allowedRoots`, SHA-256 хешированием токенов и rate limit по IP с проверкой доверенных прокси.
- **Инициализация воркспейса и git worktree.** `workspace_init` и `workspace_info` с привязкой к каноническому корню, защитой от симлинков, безопасным `git status` без `core.fsmonitor` и ограниченным чтением `MEMORY.md` до 25 КБ, плюс `worktree_enter` и `worktree_exit` для изолированных веток в `.justnewmcp/worktrees/` с отключёнными git-хуками и внешними фильтрами.
- **Файлы, поиск и чекпоинты.** `read_file` с нумерацией строк и проверкой UTF-8 и бинарников, `edit_file` с обязательным чтением до правки, атомарный `multi_edit`, `write_file`, `glob_files` и `grep_files` с поддержкой `.gitignore`, а также `checkpoint_list` и `checkpoint_rewind` с правами `0700` и `0600` на POSIX.
- **Безопасная работа с `.env`.** Шаблоны вроде `.env.example` читаются по умолчанию. Реальные `.env` закрыты от прямого чтения и обслуживаются через `read_available_envs` с именами и длиной значений, `set_env_var` с многострочным парсером и чекпоинтами, плюс тумблеры `allowEnvReading` и `askHumanAllowance`.
- **Белый список команд, фоновые задачи и опциональный шелл.** `run_allowed_cmd` запускает бинарники напрямую через `Bun.spawn` с массивом `argv` без шелла, поддерживает `background: true`, `cmd_status` с чтением хвоста лога и `task_stop` с завершением процесс-группы, очищает `JUSTNEWMCP_*` и выгружает логи длиннее 30 тысяч символов в `.justnewmcp/logs/` с правами `0600`. Опциональный `run_shell` для Bash и PowerShell скрыт и выключен до явного включения `allowShell: true`.
- **Задачи и режим плана.** Серверные `task_create`, `task_update`, `task_list` и `task_get` с проверкой циклов зависимостей и лимитом в 500 задач, а также программный read-only режим `plan_enter` и `plan_exit`.
- **Инструменты памяти проекта.** `memory_read`, `memory_write` и `memory_search` по `MEMORY.md` и тематическим папкам с соблюдением `deniedPathPatterns`, синхронной записью через один дескриптор с `O_NOFOLLOW` и очередью блокировок на параллельные `append`.
- **Диагностика и навигация через LSP.** `lsp_diagnostics`, `lsp_definition` и `lsp_references` поверх настроенных stdio языковых серверов с байтовым разбором UTF-8 `Content-Length`, поддержкой push и pull диагностик, фильтрацией URI по границам воркспейса, idle-таймаутом и восстановлением после падения.
- **Ленивая загрузка `tool_search`.** Опциональный режим `deferredTools: true` отдаёт на старте только базовые инструменты и `tool_search`, изолирует активации по `Mcp-Session-Id` и отправляет `notifications/tools/list_changed` по Streamable HTTP SSE.
- **CI и проверки безопасности.** Прогоны на Ubuntu и Windows с `bun fmt --check`, `bun check` и `bun test --check`, плюс CodeQL, Semgrep OSS, Gitleaks, OSV-Scanner, `bun audit`, Dependency Review, `actionlint` с `zizmor` и Dependabot.

## Быстрый старт

Скопируйте `config.example.json` в `config.json`, укажите `allowedRoots`, `publicUrl` и случайный 32-байтовый `oauth.clientSecret`, затем запустите сервер:

```bash
bun install
JUSTNEWMCP_CONFIG=./config.json bun run start
```

## Лицензия

MIT. Подробности в [LICENSE](../../LICENSE).
