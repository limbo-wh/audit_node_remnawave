# remnawave-node-audit

Bash-агент для нод [Remnawave](https://docs.rw): базовый hardening хоста +
мониторинг с уведомлениями в Telegram. Ставится одной командой, обнаруживает
24+ типов проблем, шлёт алерты с cooldown и recovery, имеет интерактивную
TUI-панель управления.

## Quick start

На свежей VPS (Ubuntu 22.04 / 24.04) под root:

```bash
sudo apt-get install -y git
sudo git clone https://github.com/limbo-wh/audit_node_remnawave.git /opt/remnawave-audit
sudo /opt/remnawave-audit/install.sh
```

Установщик спросит токен бота, chat_id, имя ноды, TZ — и через ~3 минуты:

- ✅ Hardening: UFW + fail2ban + auto-upgrades + NTP (с fallback на NTS/htpdate)
- ✅ systemd-таймер каждые 2 минуты
- ✅ Дневная сводка в 08:00 (TZ из конфига)
- ✅ Тестовое сообщение в Telegram

## Использование

```bash
sudo remnawave-audit          # интерактивная панель (TUI)
sudo remnawave-audit --once   # CLI, как делает таймер
```

**TUI-меню** (`sudo remnawave-audit`):
- Диагностика, live-логи, health JSON, systemd-статус
- Тестирование Telegram и алертов (6 видов тестов с авто-recovery)
- Управление портами (show / sync drift)
- Настройки (TZ, NTP, edit config)
- Обслуживание (update, reboot, rollback, uninstall)

**Прямой CLI** (для скриптов и автоматизации):

```bash
sudo remnawave-audit --once          # один прогон
sudo remnawave-audit --diagnose      # все метрики в stdout
sudo remnawave-audit --test-notify   # тестовое сообщение
sudo remnawave-audit --test-alert    # симуляция CRIT/WARN/INFO/RECOVERY
sudo remnawave-audit --show-ports    # таблица портов
sudo remnawave-audit --sync-ports    # починить port drift
sudo remnawave-audit --health        # JSON для внешнего watchdog
sudo remnawave-audit --self-update   # git pull + apply
sudo remnawave-audit --rollback --yes
sudo remnawave-audit --auto-recover  # docker compose up при падении
```

## Что мониторится

| Категория | Проверки |
|---|---|
| **Контейнер** | существование, status, restart count, health, CPU%, RAM%, image digest |
| **Сеть** | NODE_PORT слушает, established с панелью, внешний IP (3 источника, кворум), ping |
| **Система** | LA, RAM, диск `/` и `/var/lib/docker`, inode, uptime, reboot-required |
| **Время** | NTP synchronized, chrony offset |
| **Сертификаты** | nodeCertPem/caCertPem из SECRET_KEY → openssl x509 enddate |
| **Логи** | docker logs since-last-run → ERROR / FATAL / panic / tls fail |
| **Безопасность** | UFW status, fail2ban, failed SSH (с админским whitelist), новые users в /etc/passwd |
| **Целостность** | sha256 docker-compose.yml, docker manifest inspect (в дневной сводке) |
| **Port drift** | NODE_PORT в compose vs config vs UFW vs реально слушающие xray-порты |

## Алерты

| Severity | Когда | Cooldown |
|---|---|---|
| 🔴 **CRITICAL** | контейнер упал, NODE_PORT не слушает, UFW disabled, NTP сломан, диск >95% | 15 мин |
| 🟡 **WARNING** | CPU/RAM/disk над порогом, ERROR в логах, port drift, ssh brute, сертификат <30 дней | 1 час |
| 🟢 **INFO** | дневная сводка, ротация SECRET_KEY, доступное обновление образа | без |
| ✅ **RECOVERY** | алерт исчез на 3 цикла подряд (~6 мин стабильности) | без |

Каждое сообщение с заголовком `[<NODE_NAME> / <IP>]`, parse_mode HTML, на русском.
Offline queue если Telegram временно недоступен. Локальный JSON-лог `/var/log/remnawave-audit/alerts.log`.

## Hardening при установке

| Модуль | Что делает | Защита |
|---|---|---|
| **UFW** | default deny incoming, allow [SSH из sshd_config + NODE_PORT + INBOUND_PORTS + EXTRA] | sanity-check SSH в whitelist перед `ufw enable`; subset-проверка существующих правил |
| **fail2ban** | jail [sshd], bantime 1h, maxretry 5, ignoreip из SSH_ADMIN_IPS | защита от bruteforce |
| **unattended-upgrades** | только `-security`, без auto-reboot | автопатчи без сюрпризов |
| **NTP** | timedatectl set-ntp → fallback chrony+NTS (TCP/443) → fallback htpdate (HTTPS) | работает даже на VPS с заблокированным UDP/123 |

Перед изменениями делается snapshot в `/var/lib/remnawave-audit/backup/<ts>/` (iptables, fail2ban, sshd_config, apt configs).
Откат: `sudo remnawave-audit --rollback`.

## Что НЕ делает

- Не ставит саму ноду Remnawave (для этого https://docs.rw/docs/install/remnawave-node)
- Не трогает `sshd_config` (если используете пароль — отдельно настройте ключи)
- Не правит UFW автоматически при port drift — только присылает готовую команду
- Не рестартит контейнер без явного флага `--auto-recover`
- Не реализует automatic-reboot после security-патчей (только напоминает в meню/сводке)

## Конфиг

`/etc/remnawave-audit/audit.conf` — секреты (mode 600, owner root).
В git только `audit.conf.example` с плейсхолдерами.

Поля: `BOT_TOKEN`, `ADMIN_CHAT_ID` (CSV), `NODE_NAME`, `TZ`, `NODE_PORT`,
`INBOUND_PORTS`, `EXTRA_PORTS_WHITELIST`, `SSH_ADMIN_IPS`, `THRESHOLD_CPU/RAM/DISK`,
`COOLDOWN_*_SEC`, `EXTERNAL_PROBE_URL`, `AUTO_RECOVER`.

## Архитектура

```
audit.sh           # CLI entry point, все --флаги
menu.sh            # Интерактивное TUI
install.sh         # Оркестратор установки (preflight → hardening → systemd → smoke-test)
uninstall.sh       # Удаление (--purge для конфига/состояния/логов)
lib/
├── secrets.sh     # маскирование токенов в любом выводе
├── util.sh        # логирование, traps, helpers
├── state.sh       # atomic JSON key/value (state.json)
├── checks.sh      # 24+ проверок (контейнер/сеть/система/время/сертификаты/безопасность)
├── ports.sh       # port drift detection + интерактивный sync + wizard
├── notify.sh      # Telegram + cooldown + offline queue + recovery hysteresis + локализация
├── preflight.sh   # sanity checks до изменений в системе
└── hardening.sh   # UFW + fail2ban + unattended-upgrades + NTP + backup/rollback
systemd/           # 4 unit-файла (audit.timer 2 мин + audit-daily.timer 08:00)
logrotate/         # ротация alerts.log (30 дней, gzip)
.github/workflows/ # ShellCheck CI
```

## Troubleshooting

| Симптом | Решение |
|---|---|
| `🟡 certs_decode_failed` | `SECRET_KEY` имеет нестандартный формат. Проверь `docker inspect remnanode --format '{{range .Config.Env}}{{println .}}{{end}}' \| grep SECRET_KEY` |
| NTP не синкается | Меню → 10 (Установить NTP) — автоматически перейдёт на NTS, при провале — на htpdate |
| Telegram fail | Открыть чат с ботом и нажать `/start`; проверить `BOT_TOKEN` |
| `Lock conflict` | Read-only actions (`--diagnose/--health/--show-ports`) lock не берут — проблема при write actions, ждёт таймер |
| `Another instance is running` в systemd | После `--upgrade` race condition исправлен |

## Очистка и переустановка

```bash
# Откатить hardening (UFW disable + убрать fail2ban jail):
sudo remnawave-audit --rollback --yes

# Удалить скрипт (конфиг и логи остаются):
sudo /opt/remnawave-audit/uninstall.sh

# Полное удаление (с конфигом, state, логами):
sudo /opt/remnawave-audit/uninstall.sh --purge --yes
sudo rm -rf /opt/remnawave-audit

# Переустановка с нуля:
sudo /opt/remnawave-audit/audit.sh --rollback --yes 2>/dev/null || true
sudo /opt/remnawave-audit/uninstall.sh --purge --yes
sudo rm -rf /opt/remnawave-audit
sudo git clone https://github.com/limbo-wh/audit_node_remnawave.git /opt/remnawave-audit
sudo /opt/remnawave-audit/install.sh
```

## Статус

**v1.0.0 — production ready.** Прошёл боевое тестирование на ноде Remnawave
(Ubuntu 22.04, Финляндия): pre-flight, hardening, NTP с fallback на NTS+htpdate,
24+ проверок, port drift detection, recovery hysteresis, offline queue, TUI с
интерактивными trigger-тестами.

См. полный список изменений в [CHANGELOG.md](CHANGELOG.md).
