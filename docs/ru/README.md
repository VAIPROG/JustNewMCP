# JustNewMCP

[English README](../../README.md) · [Архитектура](./architecture.md)

Удаленный MCP сервер, который превращает любую чат-модель с поддержкой MCP в локального кодинг-агента. Написан на TypeScript под Bun 1.4+ для Linux и Windows, с авторизацией OAuth 2.1 и рабочей моделью по принципам Claude Code.

## Зачем мы это делаем

Чат-клиенты уже умеют подключать MCP, но большинство локальных серверов сводятся к сырому чтению и записи файлов. В итоге модель гадает пути, переписывает файлы целиком и работает без памяти и отката. JustNewMCP собирает недостающую среду в одном локальном сервере: ограниченные рабочие корни, точечные правки с чекпоинтами, память проекта, трекер задач и белый список команд.

## Статус

Первый этап завершен и смерджен в `main`: 43 теста проходят на Linux и Windows, открытых алертов Code Scanning нет. Разработка перешла ко второму этапу.

### Уже готово в `main`

- **Авторизация OAuth 2.1.** Встроенный сервер на эндпоинтах `/.well-known/oauth-protected-resource`, `/.well-known/oauth-authorization-server`, `/oauth/authorize`, `/oauth/token` и `/oauth/revoke` с PKCE S256, stateless `Bun.CSRF`, точным сравнением callback URI, одноразовыми кодами в файле `0600` на каждый инстанс вне `allowedRoots`, SHA-256 хешированием токенов и rate limit по IP с проверкой доверенных прокси.
- **Инициализация воркспейса и индекс памяти.** `workspace_init` и `workspace_info` с привязкой к каноническому корню, защитой от симлинков, безопасным `git status` без `core.fsmonitor` и ограниченным чтением `MEMORY.md` до 25 КБ из `.justnewmcp/memory/` или общей папки `memoryDir`.
- **Файлы, поиск и чекпоинты.** `read_file` с нумерацией строк и проверкой UTF-8 и бинарников, `edit_file` с обязательным чтением до правки, атомарный `multi_edit`, `write_file`, `glob_files` и `grep_files` с поддержкой `.gitignore`, а также `checkpoint_list` и `checkpoint_rewind` с правами `0700` и `0600` на POSIX.
- **Безопасная работа с `.env`.** Шаблоны вроде `.env.example` читаются по умолчанию. Реальные `.env` закрыты от прямого чтения и обслуживаются через `read_available_envs` с именами и длиной значений, `set_env_var` с многострочным парсером и чекпоинтами, плюс тумблеры `allowEnvReading` и `askHumanAllowance`.
- **Белый список команд.** `run_allowed_cmd` запускает бинарники напрямую через `Bun.spawn` с массивом `argv` без шелла, проверяет правила команд и аргументов, завершает повисшие процессы через `SIGTERM` и `SIGKILL`, очищает переменные `JUSTNEWMCP_*` и выгружает логи длиннее 30 тысяч символов в `.justnewmcp/logs/` с правами `0600`.
- **Задачи и режим плана.** Серверные `task_create`, `task_update`, `task_list` и `task_get` с проверкой циклов зависимостей и лимитом в 500 задач, а также программный read-only режим `plan_enter` и `plan_exit`.
- **Инструменты памяти проекта.** `memory_read`, `memory_write` и `memory_search` по `MEMORY.md` и тематическим папкам с соблюдением `deniedPathPatterns`, синхронной записью через один файловый дескриптор с `O_NOFOLLOW` и очередью блокировок на параллельные `append`.
- **CI и проверки безопасности.** Прогоны на Ubuntu и Windows с `bun fmt --check`, `bun check` и `bun test --check`, плюс CodeQL, Semgrep OSS, Gitleaks, OSV-Scanner, `bun audit`, Dependency Review, `actionlint` с `zizmor` и Dependabot.

### В разработке и в планах на Этап 2

- **Изолированные git worktree** в [#12](https://github.com/VAIPROG/JustNewMCP/issues/12). Инструменты `worktree_enter` и `worktree_exit` для работы в отдельной ветке внутри разрешенных корней.
- **Фоновые процессы и `task_stop`** в [#13](https://github.com/VAIPROG/JustNewMCP/issues/13). Фоновый режим для `run_allowed_cmd`, чтение хвоста логов и корректная остановка процессов.
- **Ленивая загрузка `tool_search`** в [#14](https://github.com/VAIPROG/JustNewMCP/issues/14). Компактный стартовый `tools/list` и подключение расширенных модулей по запросу.
- **Диагностика через LSP** в [#15](https://github.com/VAIPROG/JustNewMCP/issues/15). Инструменты `lsp_diagnostics`, `lsp_definition` и `lsp_references` поверх языковых серверов по stdio.
- **Опциональный локальный шелл** в [#16](https://github.com/VAIPROG/JustNewMCP/issues/16). Инструмент `run_shell` для Bash и PowerShell, выключенный по умолчанию.

## Лицензия

MIT. Подробности в [LICENSE](../../LICENSE).
