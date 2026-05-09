# Установка

## Требования

- Ubuntu 22.04 / 24.04
- root-доступ
- Установленная нода Remnawave (через https://docs.rw/docs/install/remnawave-node)
- Telegram-бот (создать через @BotFather), ваш chat_id

## Установка

На VPS под root:

```bash
sudo apt-get install -y git
sudo git clone https://github.com/limbo-wh/audit_node_remnawave.git /opt/remnawave-audit
sudo /opt/remnawave-audit/install.sh
```

Установщик интерактивно спросит:
- `BOT_TOKEN` (вводится скрытно)
- `ADMIN_CHAT_ID` (можно несколько через запятую: `12345,-1001234567890`)
- `NODE_NAME` (например `Finland2`)
- `TZ` (например `Europe/Moscow`)
- порты (с дефолтами из `docker-compose.yml`: SSH, NODE_PORT, инбаунды 443/8388)

Можно сразу неинтерактивно:

```bash
sudo /opt/remnawave-audit/install.sh \
  --bot-token=123:AAA... \
  --admin-id=12345 \
  --node-name=Finland2 \
  --tz=Europe/Moscow
```

## Что произойдёт

1. **Pre-flight checks** — root, ОС, наличие docker и ноды, валидность токена.
2. **Backup** текущего состояния iptables/fail2ban/sshd_config в `/var/lib/remnawave-audit/backup/<ts>/`.
3. **Hardening** — UFW (с allow-листом), fail2ban (jail для sshd), unattended-upgrades (только -security, без auto-reboot).
4. **systemd** — audit-таймер каждые 2 мин, дневная сводка в 08:00 (по TZ из конфига).
5. **logrotate** для `/var/log/remnawave-audit/*.log`.
6. **Smoke test** — тестовое сообщение в Telegram + один прогон.

В Telegram должно прийти `✅ Test from <NODE_NAME>`.

## Проверка

```bash
sudo systemctl status remnawave-audit.timer
sudo /opt/remnawave-audit/audit.sh --diagnose      # все метрики в stdout
sudo /opt/remnawave-audit/audit.sh --show-ports    # таблица портов
```

## Обновление

```bash
sudo /opt/remnawave-audit/audit.sh --self-update
```

Делает `git pull --ff-only` и переустанавливает systemd-юниты, если они изменились.
`audit.conf` не трогает.

## Откат hardening

```bash
sudo /opt/remnawave-audit/audit.sh --rollback
```

Soft rollback: `ufw disable` + удаление нашего fail2ban jail.
unattended-upgrades конфиг остаётся (он безопасный сам по себе).
Полные snapshot-ы — в `/var/lib/remnawave-audit/backup/`.

## Удаление

```bash
sudo /opt/remnawave-audit/uninstall.sh         # остановит unit'ы, оставит конфиг
sudo /opt/remnawave-audit/uninstall.sh --purge # удалит и конфиг/состояние/логи
```

## Конфиг

После установки: `/etc/remnawave-audit/audit.conf` (mode 600, владелец root).
Описание полей — в `audit.conf.example`. Никаких секретов в репо нет —
всё чувствительное живёт только на ноде.
