# Changelog

Все заметные изменения этого проекта документируются в этом файле.
Формат — [Keep a Changelog](https://keepachangelog.com/), версионирование — [SemVer](https://semver.org/lang/ru/).

## [1.2.0] — 2026-08-06

Установка на ноду с уже настроенной вручную безопасностью больше не ломается
и ничего не переопределяет.

### Added

- **`UFW_MODE=preserve`** (новое поведение по умолчанию) — правила UFW только
  дополняются, ничего не удаляется. Порт, у которого уже есть правило с любым
  source, не трогается. `UFW_MODE=reset` — прежнее поведение с пересборкой.
- **`NODE_PORT_ALLOW_FROM`** — порт связи с панелью открывается только с её
  IP/CIDR (`ufw allow from <IP> to any port <NODE_PORT> proto tcp`).
  Флаг `--node-port-allow-from=IP`.
- **`FAIL2BAN_MODE=preserve`** (по умолчанию) — если `[sshd]` jail уже объявлен
  админом, свой конфиг не пишется. Флаг `--fail2ban-mode=manage` возвращает
  управление скрипту.
- **Перенимание существующих настроек (adopt)** — установщик считывает с сервера
  и записывает в конфиг: порты в UFW вне whitelist → `EXTRA_PORTS_WHITELIST`,
  source-IP порта панели → `NODE_PORT_ALLOW_FROM`, `ignoreip` из чужих
  fail2ban-jail'ов → `SSH_ADMIN_IPS`. Отключается флагом `--no-adopt`.
- **`ports_ufw_rules()`** — разбор allow-правил UFW со значением source
  (`port|proto|from|comment`), с схлопыванием v6-дублей. Плюс
  `ports_ufw_has_port()`, `ports_ufw_source_for()`, `ports_ufw_extras_csv()`,
  `ports_fail2ban_ignoreip()`.
- **Мастер портов** показывает уже открытые в UFW порты и предлагает внести их
  в whitelist, спрашивает ограничение порта панели по IP, режим UFW и
  доверенные IP — раньше эти значения задавались только флагами.
- **`abort_expected()`** — контролируемый отказ guard'а больше не печатается как
  «Unexpected error at line N».

### Fixed

- **Пересборка UFW снимала ограничения по source-IP.** `ufw --force reset` с
  последующим `ufw allow <port>/tcp` превращал
  `allow from <IP панели> to any port 2222` в правило, открытое всему интернету.
  Теперь source-IP снимается до reset и восстанавливается после.
- **Установка падала на ноде с ручным hardening'ом.** Порты, открытые вне
  whitelist (например 80 у nginx-фронта и 8444 XHTTP), приводили к отказу
  hardening'а с exit 1. В режиме preserve они просто сохраняются.
- **`EXTRA_PORTS_WHITELIST` и `SSH_ADMIN_IPS` невозможно было задать в
  интерактивной установке** — брались только из флагов, хотя текст ошибки
  советовал прописать их в конфиг.
- **Свой fail2ban-jail молча перекрывался чужим.** fail2ban читает `jail.d` по
  алфавиту, поэтому `sshd.local` выигрывал у `remnawave-audit.local`, и
  настройки скрипта не применялись. Теперь конфликт обнаруживается.
- **`--rollback` выключал UFW, поднятый до установки.** Факт «firewall был
  активен до нас» фиксируется в state; такой UFW откатом не выключается.
- **`migrate_config()`** дополняет старые конфиги ключами `UFW_MODE`,
  `FAIL2BAN_MODE`, `NODE_PORT_ALLOW_FROM` и вызывается теперь и при повторном
  запуске установки, а не только при `--upgrade`.
- **`--ufw-force-reset` в режиме preserve** больше не игнорируется молча —
  установка сообщает, что флаг требует `--ufw-mode=reset`.

## [1.1.0] — 2026-05-20

### Added

- **AUTO_UPDATE** — авто-обновление скрипта из git раз в сутки (`AUTO_UPDATE=1` по умолчанию).
  `_auto_update_if_due()` вызывается в конце каждого прогона; интервал задаётся `AUTO_UPDATE_INTERVAL_HOURS`.
- **migrate_config()** в `install.sh --upgrade` — автодобавляет недостающие ключи в существующий `audit.conf`
  (например `AUTO_UPDATE=1`) без повторного ввода конфига.
- **fail2ban-статус в SSH brute-алерте** — если fail2ban активен, показывает кол-во забаненных IP;
  если неактивен — предлагает `ufw deny from <top_ip> to any`.
- **Вопрос про авто-обновление при `install.sh`** — включено по умолчанию, предлагается отключить (`[y/N]`).
- **`--self-update` отправляет Telegram-уведомление** с changelog и запускает `systemctl daemon-reload`.

### Fixed

- **IPv4 вместо IPv6** при определении внешнего IP — `curl -4` first pass; fallback без флага для IPv6-only серверов.
- **`git pull --ff-only` fallback** — при force-push upstream `--self-update` теперь автоматически
  делает `git fetch origin && git reset --hard origin/main`.
- **`--diagnose`** — пустая строка details больше не печатается.
- **`migrate_config()`** — `(( added == 0 ))` crashил `set -e`; переписано на `if/fi`.

### Changed

- **Daily summary** — CRIT-инциденты за 24ч сгруппированы отдельной строкой.
- **Recovery hysteresis** — настраивается per-key (`network_panel_link_lost` = 2 цикла, остальные = 3).

---

## [1.0.0] — 2026-05-09

Production-ready релиз. Прошёл боевое тестирование на реальной ноде Remnawave.

### Core

- **Bash-агент** для нод Remnawave с минимальным набором зависимостей
  (`bash`, `curl`, `jq`, `docker`, `ss`, `openssl`, `awk`, `sed`).
- **24+ проверок** состояния: контейнер `remnanode` (existence/status/restart-count/health/CPU/RAM/image),
  сеть (NODE_PORT, established с панелью, внешний IP с кворумом 3 источников, ping),
  система (LA/RAM/disk/inode/uptime/reboot-required), время (NTP, chrony offset),
  сертификаты (nodeCertPem/caCertPem из SECRET_KEY env), логи (since-last-run grep),
  безопасность (UFW, fail2ban, failed SSH с админским whitelist, новые users),
  целостность (sha256 docker-compose.yml, docker manifest inspect — в дневной).
- **Port drift detection** — сравнение compose vs audit.conf vs UFW vs реально
  слушающие xray-порты (через `docker top` PID + `ss -tlnpH`).

### Hardening (автоматически при `install.sh`)

- **UFW** — default deny incoming, allow whitelist (SSH из sshd_config + NODE_PORT
  + INBOUND_PORTS + EXTRA_PORTS_WHITELIST). Sanity-check: SSH порт обязан быть в
  allow-листе перед `ufw enable`. Subset-проверка существующих правил —
  идемпотентный reset если все ⊆ нашего whitelist.
- **fail2ban** — jail [sshd], bantime 1h, maxretry 5, `ignoreip` из `SSH_ADMIN_IPS`.
- **unattended-upgrades** — только `-security`, без auto-reboot, отключение `apt-listchanges`.
- **NTP** с трёхуровневым fallback:
  1. `timedatectl set-ntp` + restart timesyncd (UDP/123) — стандарт.
  2. Если не помогло → `chrony + NTS` (Cloudflare/Netnod через TCP/443) — обходит блок UDP/123.
  3. Если и это не помогло → `htpdate` (HTTP Date headers через google/github/api.telegram.org)
     с systemd-таймером каждый час — работает там, где всё остальное заблокировано.

Перед любыми изменениями — backup `/var/lib/remnawave-audit/backup/<ts>/` (iptables,
ufw status, /etc/fail2ban, sshd_config, apt configs). Soft rollback через
`audit.sh --rollback`.

### Telegram-нотификации (`lib/notify.sh`)

- `curl` к `api.telegram.org/bot<TOKEN>/sendMessage`, parse_mode HTML.
- **CSV `ADMIN_CHAT_ID`** — несколько получателей одновременно (личка + канал).
- **Cooldown** по `alert_last_sent_<key>` в state: CRIT 15 мин, WARN 1 час.
- **Recovery hysteresis** — 3 цикла подряд OK (~6 минут) перед `✅`. Защита от флапа.
- **Локализация** — все 30+ ключей переведены в человеко-понятные русские заголовки.
- **Offline queue** в `/var/lib/remnawave-audit/queue/<unix>.json` с FIFO дренингом
  и trim до 100 файлов при overflow.
- **Локальный JSON-лог** `/var/log/remnawave-audit/alerts.log` (logrotate 30 дней, gzip).
- **HTML-escape** всего пользовательского контента, truncate до 3800 символов.
- **Маскирование секретов** (`lib/secrets.sh`): `BOT_TOKEN`, base64-блобы,
  явно зарегистрированные значения — заменяются на `***` в любом выводе скрипта.

### Установка (`install.sh`)

- **Pre-flight checks** (root, Ubuntu 22.04/24.04, docker daemon, `/opt/remnanode/`
  с `remnawave/node`, ≥1 GB на `/`, sshd_config Port парсится, api.telegram.org
  достижим, BOT_TOKEN валиден через `getMe`, предупреждение о docker-bridge).
- **Авто-установка зависимостей** (jq, curl, ca-certificates) до preflight.
- **Интерактивный сбор** или флаги: `--bot-token=`, `--admin-id=`, `--node-name=`,
  `--tz=`, `--node-port=`, `--inbound-ports=`, `--extra-ports=`, `--ssh-admin-ips=`,
  `--probe-url=`, `--threshold-*=`.
- **Port wizard** — интерактивный диалог про SSH/NODE_PORT/инбаунды (s/c/a) с
  подхватом `NODE_PORT` из `/opt/remnanode/docker-compose.yml`.
- **Авто-синхронизация TZ хоста** под TZ из конфига (`timedatectl set-timezone`)
  с подтверждением. Флаги `--set-host-timezone` / `--keep-host-timezone`.
- **Resumable** — повторный запуск подхватывает существующий `audit.conf`,
  не задаёт вопросы заново.
- **Режимы**: `--upgrade` (только unit'ы и hardening), `--hardening-only`,
  `--skip-hardening`, `--non-interactive`, `--force`. Все skip-флаги для модулей
  hardening: `--skip-ufw`, `--skip-fail2ban`, `--skip-unattended`, `--skip-ntp`.
- **Запись `audit.conf`** под `umask 077` (защита от race chmod) с `printf '%q'`
  quoting каждого значения.
- **Smoke test** — `--test-notify` + `--once` после установки.

### TUI и CLI (`menu.sh` + `audit.sh`)

- `sudo remnawave-audit` — **интерактивная панель** (TUI на чистом bash, без
  зависимостей). Симлинк `/usr/local/bin/remnawave-audit` создаётся автоматически.
- 14 пунктов меню: диагностика, live-tail логов, health JSON, systemd-статус,
  тестирование (6 видов: простое сообщение, симуляция всех severity, реальные
  CPU/Disk/User/Port триггеры с авто-recovery), порты (show + sync), редактирование
  конфига, смена TZ, NTP setup, обновление, перезагрузка хоста, откат hardening,
  полное удаление.
- **Live статус** в шапке меню: имя ноды, TZ, состояние таймера, последний прогон
  (статус + CRIT/WARN счётчики + время «N мин назад»), глубина offline queue.
- **CLI actions**: `--once`, `--diagnose`, `--test-notify`, `--test-alert`,
  `--show-ports`, `--sync-ports`, `--daily-summary`, `--health`, `--self-update`,
  `--rollback [--yes]`, `--auto-recover`, `--version`.
- **Daily summary** — uptime контейнера/хоста, число сессий, диск/RAM/LA, сертификат,
  hardening status, инциденты за 24ч из alerts.log, image-update, reboot-required.
- **`--health`** — JSON со статусом для внешнего watchdog.
- **`--self-update`** — `git pull --ff-only` + `install.sh --upgrade` при
  изменении systemd unit'ов; INFO в Telegram при изменении `lib/hardening.sh`
  (требует ручного `install.sh --hardening-only`).
- **`--auto-recover`** — rate-limited `docker compose up -d` при CRIT
  container_status (max 3/час, защита через counter+window в state).

### systemd / logrotate

- 4 unit-файла (templates с `__SCRIPT_DIR__` / `__TZ__`):
  - `remnawave-audit.{service,timer}` — каждые 2 мин (`OnUnitActiveSec=120`,
    `RandomizedDelaySec=15`).
  - `remnawave-audit-daily.{service,timer}` — 08:00 в TZ из конфига
    (`OnCalendar=*-*-* 08:00:00 <TZ>` — DST-safe, требует systemd 233+).
- **`SuccessExitStatus=0 1 2`** — exit 1 (warning) и 2 (critical) считаются
  штатными, в journalctl `Finished` вместо `Failed`.
- **logrotate** для `/var/log/remnawave-audit/*.log` — daily, rotate 30, gzip
  с delaycompress.

### Качество и безопасность

- `set -Eeuo pipefail`, `IFS=$'\n\t'`, traps на ERR и EXIT.
- `flock -n` на `/run/remnawave-audit.lock` — read-only actions
  (`--diagnose/--show-ports/--health`) lock не берут (для совместимости с
  системным таймером).
- ShellCheck в CI (`.github/workflows/shellcheck.yml`).
- `.gitattributes` для гарантированного LF в `.sh`/`.service`/`.timer`.
- `.gitignore` для секретов и состояния (audit.conf, state.json, queue/, backup/, *.log).

## [0.1.0] — 2026-05-08 (initial scaffold)

Скелет проекта: `audit.sh` со всеми флагами (заглушки), `lib/util.sh`,
`lib/secrets.sh`, `audit.conf.example`, `install.sh`/`uninstall.sh` (заглушки),
README, INSTALL, ShellCheck в CI, `.gitignore`.
