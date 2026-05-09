#!/usr/bin/env bash
# menu.sh — интерактивная панель управления remnawave-node-audit.
#
# Без аргументов — показывает интерактивную TUI-панель.
# С аргументами — прозрачно пробрасывает их в audit.sh
# (для systemd-таймера и обратной совместимости с CLI).

set -Eeuo pipefail
IFS=$'\n\t'

# readlink -f нужен потому что menu.sh обычно запускается через симлинк
# /usr/local/bin/remnawave-audit → /opt/remnawave-audit/menu.sh, и без resolve
# SCRIPT_DIR будет /usr/local/bin/, а audit.sh там нет.
readonly SCRIPT_DIR="$(cd -P "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
readonly AUDIT_SH="${SCRIPT_DIR}/audit.sh"
readonly INSTALL_SH="${SCRIPT_DIR}/install.sh"
readonly UNINSTALL_SH="${SCRIPT_DIR}/uninstall.sh"
readonly CONFIG_PATH="/etc/remnawave-audit/audit.conf"
readonly LOG_DIR="/var/log/remnawave-audit"
readonly STATE_DIR="/var/lib/remnawave-audit"

# --- Прозрачный pass-through в audit.sh для CLI и systemd ---
if (( $# > 0 )); then
  exec "${AUDIT_SH}" "$@"
fi

# --- ANSI-цвета ---
if [[ -t 1 ]]; then
  C_RED=$'\033[31m'   C_GRN=$'\033[32m'   C_YLW=$'\033[33m'
  C_BLU=$'\033[34m'   C_CYN=$'\033[36m'   C_DIM=$'\033[2m'
  C_BLD=$'\033[1m'    C_RST=$'\033[0m'
else
  C_RED="" C_GRN="" C_YLW="" C_BLU="" C_CYN="" C_DIM="" C_BLD="" C_RST=""
fi

# --- Helpers ---

require_root() {
  if (( EUID != 0 )); then
    printf '%sНужно запускать через sudo:%s sudo %s\n' "$C_RED" "$C_RST" "$0" >&2
    exit 1
  fi
}

pause() {
  printf '\n%s[Enter — назад в меню]%s ' "$C_DIM" "$C_RST"
  read -r _ </dev/tty || true
}

confirm() {
  local prompt="${1:-Продолжить?}"
  local default="${2:-N}"  # Y или N
  local hint="[y/N]"
  [[ "$default" == "Y" ]] && hint="[Y/n]"
  printf '%s %s: ' "$prompt" "$hint"
  local ans
  read -r ans </dev/tty
  if [[ "$default" == "Y" ]]; then
    [[ "$ans" != "n" && "$ans" != "N" ]]
  else
    [[ "$ans" == "y" || "$ans" == "Y" ]]
  fi
}

# Источник конфига для отображения статуса (NODE_NAME, TZ).
load_conf_safe() {
  if [[ -r "$CONFIG_PATH" ]]; then
    # shellcheck disable=SC1090
    . "$CONFIG_PATH" 2>/dev/null || true
  fi
}

print_header() {
  clear
  cat <<HEADER
${C_CYN}${C_BLD}╔══════════════════════════════════════════════════════════╗
║          remnawave-node-audit — control panel            ║
╚══════════════════════════════════════════════════════════╝${C_RST}
HEADER
}

print_status_block() {
  load_conf_safe
  local node="${NODE_NAME:-?}" tz="${TZ:-?}"

  local timer_state="—"
  if systemctl is-active --quiet remnawave-audit.timer 2>/dev/null; then
    timer_state="${C_GRN}active${C_RST}"
  else
    timer_state="${C_RED}не запущен${C_RST}"
  fi

  local last_status="?" n_crit=0 n_warn=0 last_ts=0
  if [[ -r "${STATE_DIR}/state.json" ]] && command -v jq >/dev/null 2>&1; then
    last_status="$(jq -r '.last_run_status // "?"' "${STATE_DIR}/state.json" 2>/dev/null || echo '?')"
    n_crit="$(jq -r '.last_run_n_crit // "0"' "${STATE_DIR}/state.json" 2>/dev/null || echo 0)"
    n_warn="$(jq -r '.last_run_n_warn // "0"' "${STATE_DIR}/state.json" 2>/dev/null || echo 0)"
    last_ts="$(jq -r '.last_run_unix // "0"' "${STATE_DIR}/state.json" 2>/dev/null || echo 0)"
  fi

  local last_human="никогда"
  if [[ "$last_ts" =~ ^[0-9]+$ ]] && (( last_ts > 0 )); then
    local now ago_sec
    now="$(date +%s)"
    ago_sec=$(( now - last_ts ))
    if (( ago_sec < 60 )); then
      last_human="${ago_sec}с назад"
    elif (( ago_sec < 3600 )); then
      last_human="$((ago_sec/60))мин назад"
    else
      last_human="$((ago_sec/3600))ч назад"
    fi
  fi

  local status_color="$C_GRN"
  case "$last_status" in
    critical) status_color="$C_RED" ;;
    warning)  status_color="$C_YLW" ;;
    ok)       status_color="$C_GRN" ;;
    *)        status_color="$C_DIM" ;;
  esac

  local queue_depth=0
  [[ -d "${STATE_DIR}/queue" ]] && \
    queue_depth="$(find "${STATE_DIR}/queue" -maxdepth 1 -type f -name '*.json' 2>/dev/null | wc -l)"

  cat <<STATUS
  ${C_BLD}Узел:${C_RST}        ${node}    ${C_DIM}(TZ: ${tz})${C_RST}
  ${C_BLD}Таймер:${C_RST}      ${timer_state}    ${C_DIM}(каждые 2 мин)${C_RST}
  ${C_BLD}Послед.прогон:${C_RST} ${status_color}${last_status}${C_RST}    ${C_DIM}${last_human}, CRIT=${n_crit}, WARN=${n_warn}${C_RST}
  ${C_BLD}Очередь TG:${C_RST}  ${queue_depth} в pending
STATUS
}

print_menu() {
  cat <<MENU

${C_BLD}═══ ДИАГНОСТИКА ═══${C_RST}
  ${C_CYN}1)${C_RST} Полная проверка (diagnose) — все метрики на экран
  ${C_CYN}2)${C_RST} Live-просмотр алертов (tail -f /var/log/.../alerts.log)
  ${C_CYN}3)${C_RST} Health JSON (для внешнего watchdog)
  ${C_CYN}4)${C_RST} systemd: статус таймера и последний прогон

${C_BLD}═══ TELEGRAM И ПОРТЫ ═══${C_RST}
  ${C_CYN}5)${C_RST} Тестирование Telegram и алертов (6 видов тестов)
  ${C_CYN}6)${C_RST} Таблица портов (declared / listening / UFW)
  ${C_CYN}7)${C_RST} Синхронизировать порты (если есть drift)

${C_BLD}═══ НАСТРОЙКИ ═══${C_RST}
  ${C_CYN}8)${C_RST} Редактировать audit.conf (nano)
  ${C_CYN}9)${C_RST} Сменить часовой пояс (TZ)
  ${C_CYN}10)${C_RST} Установить NTP (timedatectl set-ntp true)

${C_BLD}═══ ОБСЛУЖИВАНИЕ ═══${C_RST}
  ${C_CYN}11)${C_RST} Обновить скрипт (git pull + install --upgrade)
  ${C_CYN}12)${C_RST} Перезагрузить хост (если требуется reboot-required)
  ${C_CYN}13)${C_RST} Откатить hardening (UFW disable + убрать наш fail2ban jail)
  ${C_CYN}14)${C_RST} Полное удаление (uninstall --purge)

  ${C_DIM}0)  Выход${C_RST}

MENU
}

# --- Действия ---

action_diagnose() {
  print_header
  printf '%s═══ Diagnose ═══%s\n\n' "$C_BLD" "$C_RST"
  "${AUDIT_SH}" --diagnose
  pause
}

action_live_logs() {
  print_header
  printf '%s═══ Live-просмотр логов ═══%s\n\n' "$C_BLD" "$C_RST"
  printf 'Что показать?\n'
  printf '  %s1)%s Алерты в Telegram (alerts.log) — отправленные сообщения\n' "$C_CYN" "$C_RST"
  printf '  %s2)%s systemd journal (journalctl -u remnawave-audit.service -f)\n' "$C_CYN" "$C_RST"
  printf '  %s0) Назад%s\n\n' "$C_DIM" "$C_RST"
  printf 'Выбор: '
  local sub
  read -r sub </dev/tty
  case "$sub" in
    1)
      if [[ ! -f "${LOG_DIR}/alerts.log" || ! -s "${LOG_DIR}/alerts.log" ]]; then
        printf '\n%sФайл %s/alerts.log пустой или отсутствует.%s\n' "$C_YLW" "$LOG_DIR" "$C_RST"
        printf 'Это нормально если ещё не было алертов или cooldown подавил их.\n'
        printf 'Telegram-уведомления складываются сюда только при отправке (CRIT/WARN/recovery).\n'
        pause
        return
      fi
      printf '\n%sCtrl+C — выход. Последние 20 строк + новые:%s\n\n' "$C_DIM" "$C_RST"
      trap 'true' INT
      tail -n 20 -f "${LOG_DIR}/alerts.log" | (jq -C 2>/dev/null || cat)
      trap - INT
      ;;
    2)
      printf '\n%sCtrl+C — выход.%s\n\n' "$C_DIM" "$C_RST"
      trap 'true' INT
      journalctl -u remnawave-audit.service -f -n 30 --no-pager 2>/dev/null || true
      trap - INT
      ;;
    *) return ;;
  esac
  pause
}

action_health() {
  print_header
  printf '%s═══ Health JSON ═══%s\n\n' "$C_BLD" "$C_RST"
  "${AUDIT_SH}" --health | jq -C 2>/dev/null || "${AUDIT_SH}" --health
  pause
}

action_systemd_status() {
  print_header
  printf '%s═══ systemd: таймер и последний прогон ═══%s\n\n' "$C_BLD" "$C_RST"
  systemctl status remnawave-audit.timer --no-pager 2>/dev/null || true
  printf '\n'
  systemctl status remnawave-audit-daily.timer --no-pager 2>/dev/null || true
  printf '\n%s--- Последние 15 запусков основного сервиса ---%s\n' "$C_BLD" "$C_RST"
  journalctl -u remnawave-audit.service -n 15 --no-pager 2>/dev/null || true
  pause
}

_reset_cooldown_for() {
  local key="$1"
  local f="${STATE_DIR}/state.json"
  [[ -f "$f" ]] || return 0
  local tmp; tmp="$(mktemp)"
  jq --arg k "alert_last_sent_${key}" 'del(.[$k])' "$f" > "$tmp" 2>/dev/null && mv "$tmp" "$f" || rm -f "$tmp"
  chmod 600 "$f" 2>/dev/null || true
}

# Прогнать --once N раз с интервалом, для recovery hysteresis (3 подряд).
_run_audit_n_times() {
  local n="${1:-3}" delay="${2:-5}" i
  for ((i=1; i<=n; i++)); do
    printf '  Прогон %d/%d... ' "$i" "$n"
    if "${AUDIT_SH}" --once 2>/dev/null; then
      printf '%sok%s\n' "$C_GRN" "$C_RST"
    else
      printf '%s(параллельный таймер, пропускаем)%s\n' "$C_DIM" "$C_RST"
    fi
    (( i < n )) && sleep "$delay"
  done
}

# Универсальный шаблон trigger'а: меняем поле в audit.conf → прогон → ждём
# подтверждения от пользователя → возвращаем поле → 3 прогона для recovery.
_run_threshold_trigger() {
  local label="$1"           # "CPU" / "Disk"
  local conf_key="$2"        # "THRESHOLD_CPU"
  local trigger_value="$3"   # "1"
  local alert_key="$4"       # "container_cpu_high" — для сброса cooldown

  local orig
  orig="$(grep -E "^${conf_key}=" "$CONFIG_PATH" | head -1 | cut -d= -f2)"
  [[ -z "$orig" ]] && orig=80

  printf '%s═══ Trigger: %s%s\n\n' "$C_BLD" "$label" "$C_RST"
  printf '1. Сбрасываю cooldown для %s в state.json\n' "$alert_key"
  _reset_cooldown_for "$alert_key"

  printf '2. Понижаю %s: %s → %s в %s\n' "$conf_key" "$orig" "$trigger_value" "$CONFIG_PATH"
  sed -i "s/^${conf_key}=.*/${conf_key}=${trigger_value}/" "$CONFIG_PATH"

  printf '3. Запускаю прогон сейчас (вместо ожидания таймера 2 мин)\n'
  "${AUDIT_SH}" --once 2>/dev/null || true

  printf '\n%s→ Проверь Telegram. Должен прийти 🟡 WARN с упоминанием %s.%s\n' "$C_GRN" "$label" "$C_RST"
  printf '  Жми Enter после получения. Тогда верну threshold обратно.\n'
  read -r _ </dev/tty

  printf '\n4. Возвращаю %s обратно: %s → %s\n' "$conf_key" "$trigger_value" "$orig"
  sed -i "s/^${conf_key}=.*/${conf_key}=${orig}/" "$CONFIG_PATH"

  printf '5. Гоняю прогон 3 раза (для recovery hysteresis)\n'
  _run_audit_n_times 3 5

  printf '\n%s→ Должен прийти ✅ RECOVERY (через 3 прогона стабильности).%s\n' "$C_GRN" "$C_RST"
  printf '  Если не пришёл сразу — таймер сам прогонит ещё пару раз.\n'
}

_run_user_trigger() {
  local username="testuser_alert_$$"
  printf '%s═══ Trigger: новый пользователь%s\n\n' "$C_BLD" "$C_RST"
  printf '1. Сбрасываю cooldown\n'
  _reset_cooldown_for "security_new_user"

  printf '2. Создаю временного пользователя: %s\n' "$username"
  useradd -M -s /usr/sbin/nologin "$username" 2>/dev/null

  printf '3. Запускаю прогон\n'
  "${AUDIT_SH}" --once 2>/dev/null || true

  printf '\n%s→ Проверь Telegram. Должен прийти 🔴 CRIT "Новый пользователь: %s".%s\n' "$C_GRN" "$username" "$C_RST"
  printf '  Жми Enter — удалю пользователя.\n'
  read -r _ </dev/tty

  printf '\n4. Удаляю пользователя\n'
  userdel -r "$username" 2>/dev/null || userdel "$username" 2>/dev/null

  printf '5. 3 прогона для recovery\n'
  _run_audit_n_times 3 5
  printf '\n%s→ Должен прийти ✅ RECOVERY.%s\n' "$C_GRN" "$C_RST"
}

_run_port_trigger() {
  local port=12345
  printf '%s═══ Trigger: лишний открытый порт%s\n\n' "$C_BLD" "$C_RST"
  if ! command -v python3 >/dev/null 2>&1; then
    printf '%spython3 не установлен — нужен для запуска тест-listener.%s\n' "$C_RED" "$C_RST"
    printf 'Поставить: apt install -y python3-minimal\n'
    return
  fi

  # NB: ports_drift_check ловит только то что слушает xray (по PID).
  # Чтобы триггер сработал, нужно чтобы listener был child процесса
  # remnanode. Это сложно. Поэтому проверяем через check_security_open_ports
  # — но он удалён в недавнем коммите. Этот тест может не вызвать алерт
  # если ваша версия скрипта не имеет такой проверки. В таком случае
  # подсветим что test не triggered, а не падать молча.

  printf '1. Сбрасываю cooldown\n'
  _reset_cooldown_for "ports_unknown_listening_${port}"
  _reset_cooldown_for "security_unknown_ports"

  printf '2. Запускаю TCP-listener на порту %s (Python, в фоне на 5 мин)\n' "$port"
  python3 -c "
import socket, time, sys
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', $port))
    s.listen(1)
    time.sleep(300)
except Exception as e:
    print('listener error:', e, file=sys.stderr)
" >/dev/null 2>&1 &
  local listener_pid=$!
  sleep 2

  if ! kill -0 "$listener_pid" 2>/dev/null; then
    printf '%sНе удалось поднять listener (порт занят?)%s\n' "$C_RED" "$C_RST"
    return
  fi

  printf '3. Запускаю прогон\n'
  "${AUDIT_SH}" --once 2>/dev/null || true

  printf '\n%s→ Проверь Telegram (через 5-10 сек).%s\n' "$C_GRN" "$C_RST"
  printf '  ⚠ Этот тест ловит ТОЛЬКО xray-порты. Питон-listener не xray,\n'
  printf '    поэтому может НЕ вызвать наш алерт ports_unknown_listening.\n'
  printf '    Это норма — тест полезен скорее как проверка детекции в принципе.\n'
  printf '  Жми Enter — закрою listener.\n'
  read -r _ </dev/tty

  printf '\n4. Закрываю listener (PID %s)\n' "$listener_pid"
  kill "$listener_pid" 2>/dev/null || true
  wait "$listener_pid" 2>/dev/null || true

  printf '5. 3 прогона для recovery (если был алерт)\n'
  _run_audit_n_times 3 5
}

action_test_notify() {
  print_header
  printf '%s═══ Тестирование Telegram и алертов ═══%s\n\n' "$C_BLD" "$C_RST"
  printf '%sПростые проверки (без модификации системы):%s\n' "$C_BLD" "$C_RST"
  printf '  %s1)%s Простое тестовое сообщение (1 шт.) — проверка связи\n' "$C_CYN" "$C_RST"
  printf '  %s2)%s Симуляция всех алертов — CRIT/WARN/INFO/RECOVERY (4 шт.)\n' "$C_CYN" "$C_RST"
  printf '\n%sРеальные триггеры (с авто-восстановлением):%s\n' "$C_BLD" "$C_RST"
  printf '  %s3)%s CPU threshold — 🟡 WARN + ✅ recovery\n' "$C_CYN" "$C_RST"
  printf '  %s4)%s Disk threshold — 🟡 WARN + ✅ recovery\n' "$C_CYN" "$C_RST"
  printf '  %s5)%s Новый пользователь — 🔴 CRIT + ✅ recovery\n' "$C_CYN" "$C_RST"
  printf '  %s6)%s Лишний открытый порт — 🟡 WARN + ✅ recovery\n' "$C_CYN" "$C_RST"
  printf '\n  %s0) Назад%s\n\n' "$C_DIM" "$C_RST"
  printf 'Выбор: '
  local sub
  read -r sub </dev/tty
  printf '\n'
  case "$sub" in
    1)
      "${AUDIT_SH}" --test-notify
      printf '\n%sЕсли "fail" — проверь:%s\n' "$C_YLW" "$C_RST"
      printf '  1. Открыт ли чат с ботом и нажат /start\n'
      printf '  2. Корректен ли BOT_TOKEN в %s\n' "$CONFIG_PATH"
      ;;
    2)
      "${AUDIT_SH}" --test-alert
      printf '\n%sДолжны прийти 4 сообщения: 🔴 🟡 🟢 ✅%s\n' "$C_BLD" "$C_RST"
      ;;
    3) _run_threshold_trigger "CPU"  "THRESHOLD_CPU"  "1"  "container_cpu_high" ;;
    4) _run_threshold_trigger "Disk" "THRESHOLD_DISK" "10" "system_disk_high" ;;
    5) _run_user_trigger ;;
    6) _run_port_trigger ;;
    *) return ;;
  esac
  pause
}

action_show_ports() {
  print_header
  "${AUDIT_SH}" --show-ports
  pause
}

action_sync_ports() {
  print_header
  printf '%s═══ Синхронизация портов ═══%s\n\n' "$C_BLD" "$C_RST"
  "${AUDIT_SH}" --sync-ports
  pause
}

action_edit_conf() {
  print_header
  printf '%s═══ Редактирование %s ═══%s\n\n' "$C_BLD" "$CONFIG_PATH" "$C_RST"
  if [[ ! -f "$CONFIG_PATH" ]]; then
    printf '%sКонфиг не найден.%s\n' "$C_RED" "$C_RST"
    pause
    return
  fi
  local editor="${EDITOR:-nano}"
  command -v "$editor" >/dev/null 2>&1 || editor="vi"
  "$editor" "$CONFIG_PATH"
  printf '\n%sЕсли поменяли пороги/порты — apply via "Обновить" (пункт 11).%s\n' "$C_DIM" "$C_RST"
  pause
}

action_change_tz() {
  print_header
  printf '%s═══ Смена часового пояса ═══%s\n\n' "$C_BLD" "$C_RST"
  load_conf_safe
  local sys_tz cur_conf_tz
  sys_tz="$(timedatectl show -p Timezone --value 2>/dev/null || echo UTC)"
  cur_conf_tz="${TZ:-UTC}"
  printf 'Сейчас:\n'
  printf '  Системная TZ хоста:  %s\n' "$sys_tz"
  printf '  TZ в audit.conf:     %s\n\n' "$cur_conf_tz"
  printf 'Введите новую TZ (например Europe/Moscow, Asia/Tashkent, или пусто чтобы отменить):\n> '
  local new_tz
  read -r new_tz </dev/tty
  if [[ -z "$new_tz" ]]; then
    printf '%sОтменено.%s\n' "$C_DIM" "$C_RST"
    pause; return
  fi
  if [[ ! -e "/usr/share/zoneinfo/${new_tz}" ]]; then
    printf '%sТакая TZ не найдена. Список: timedatectl list-timezones%s\n' "$C_RED" "$C_RST"
    pause; return
  fi
  if confirm "Установить ${new_tz} как системную TZ хоста?" Y; then
    timedatectl set-timezone "$new_tz"
    printf '%sСистемная TZ → %s%s\n' "$C_GRN" "$new_tz" "$C_RST"
  fi
  if [[ -f "$CONFIG_PATH" ]] && confirm "Заменить TZ в audit.conf на ${new_tz} и применить?" Y; then
    sed -i "s|^TZ=.*|TZ=${new_tz}|" "$CONFIG_PATH"
    "${INSTALL_SH}" --upgrade --skip-hardening
    printf '%sГотово. Daily summary теперь в 08:00 %s.%s\n' "$C_GRN" "$new_tz" "$C_RST"
  fi
  pause
}

_wait_for_ntp_sync() {
  local timeout="${1:-30}" i=0
  printf '%sЖду синхронизацию (до %sс)...%s' "$C_DIM" "$timeout" "$C_RST"
  while (( i < timeout )); do
    sleep 5
    i=$((i+5))
    printf '.'
    if timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -q '^yes$'; then
      printf ' %sсинхронизировано!%s\n' "$C_GRN" "$C_RST"
      return 0
    fi
  done
  printf ' %sтаймаут%s\n' "$C_YLW" "$C_RST"
  return 1
}

_setup_chrony_nts() {
  printf '%sСтавлю chrony и настраиваю NTS (Cloudflare через TCP/443)...%s\n' "$C_DIM" "$C_RST"
  if ! dpkg -s chrony >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq chrony >/dev/null
  fi
  systemctl disable --now systemd-timesyncd 2>/dev/null || true
  mkdir -p /etc/chrony/conf.d
  cat > /etc/chrony/conf.d/nts.conf <<'EOF'
# Managed by remnawave-audit menu — NTS over TCP/443, обходит блокировку UDP/123
server time.cloudflare.com iburst nts
server nts.netnod.se iburst nts
EOF
  systemctl enable chrony >/dev/null 2>&1
  systemctl restart chrony
  log_info_inline "chrony + NTS настроен"
}

log_info_inline() {
  printf '%s✓ %s%s\n' "$C_GRN" "$1" "$C_RST"
}

action_set_ntp() {
  print_header
  printf '%s═══ Включить NTP ═══%s\n\n' "$C_BLD" "$C_RST"
  printf 'Текущее состояние:\n'
  timedatectl | grep -E 'NTP|synchronized' || true
  printf '\n'

  if ! confirm "Включить и попробовать синхронизировать?" Y; then
    pause; return
  fi

  # Phase 1: standard NTP via timesyncd (если активен) или chrony (если уже стоит)
  timedatectl set-ntp true
  if systemctl list-unit-files systemd-timesyncd.service 2>/dev/null | grep -q 'timesyncd'; then
    systemctl restart systemd-timesyncd 2>/dev/null || true
  fi
  if systemctl is-active --quiet chrony 2>/dev/null; then
    systemctl restart chrony 2>/dev/null || true
  fi

  if _wait_for_ntp_sync 30; then
    printf '\n%sНовое состояние:%s\n' "$C_GRN" "$C_RST"
    timedatectl | grep -E 'NTP|synchronized' || true
    pause; return
  fi

  # Phase 2: fallback на chrony + NTS поверх TCP/443
  cat <<MSG

${C_YLW}Стандартный NTP (UDP/123) не работает — это типично на VPS.${C_RST}
${C_BLD}Решение: NTS — Network Time Security поверх TCP/443${C_RST}
  (Cloudflare time.cloudflare.com — обходит блокировку провайдера)

MSG
  if confirm "Установить chrony + NTS автоматически?" Y; then
    _setup_chrony_nts
    if _wait_for_ntp_sync 60; then
      printf '\n%sГотово! Синхронизировано через NTS.%s\n' "$C_GRN" "$C_RST"
      printf '\n%sДиагностика:%s\n' "$C_BLD" "$C_RST"
      chronyc tracking 2>/dev/null | head -10 || true
    else
      printf '\n%sNTS тоже заблокирован (TCP/443 к Cloudflare/Netnod).%s\n' "$C_YLW" "$C_RST"
      printf '%sПереключаюсь на htpdate (HTTP Date headers обычных сайтов)...%s\n' "$C_DIM" "$C_RST"
      if dpkg -s htpdate >/dev/null 2>&1 || \
         DEBIAN_FRONTEND=noninteractive apt-get install -y -qq htpdate >/dev/null 2>&1; then
        systemctl disable --now chrony 2>/dev/null || true
        htpdate -s -t \
          https://www.google.com \
          https://github.com \
          https://api.telegram.org \
          2>/dev/null || true

        cat > /etc/systemd/system/htpdate-sync.service <<'EOF'
[Unit]
Description=Time sync via HTTPS Date headers (htpdate fallback)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/htpdate -s -t https://www.google.com https://github.com https://api.telegram.org
TimeoutStartSec=30
EOF
        cat > /etc/systemd/system/htpdate-sync.timer <<'EOF'
[Unit]
Description=Run htpdate every hour for time sync

[Timer]
OnBootSec=2min
OnUnitActiveSec=1h
RandomizedDelaySec=5min

[Install]
WantedBy=timers.target
EOF
        systemctl daemon-reload
        systemctl enable --now htpdate-sync.timer >/dev/null 2>&1
        # state.json через jq
        if [[ -f /var/lib/remnawave-audit/state.json ]]; then
          local tmp; tmp="$(mktemp)"
          jq '. + {hardening_ntp_managed: "htpdate"}' /var/lib/remnawave-audit/state.json > "$tmp" \
            && mv "$tmp" /var/lib/remnawave-audit/state.json
          chmod 600 /var/lib/remnawave-audit/state.json
        fi
        printf '\n%sГотово! Время синхронизировано через htpdate (HTTPS).%s\n' "$C_GRN" "$C_RST"
        printf 'Таймер htpdate-sync обновляет время каждый час.\n'
        printf '%sТочность ±1 сек — этого хватает для mTLS/JWT.%s\n' "$C_DIM" "$C_RST"
        date
      else
        printf '%sНе удалось поставить htpdate. Что-то совсем сломано с интернетом.%s\n' "$C_RED" "$C_RST"
      fi
    fi
  fi
  pause
}

action_self_update() {
  print_header
  printf '%s═══ Обновление скрипта ═══%s\n\n' "$C_BLD" "$C_RST"
  "${AUDIT_SH}" --self-update
  pause
}

action_rollback() {
  print_header
  printf '%s═══ Откат hardening ═══%s\n\n' "$C_BLD" "$C_RST"
  "${AUDIT_SH}" --rollback
  pause
}

action_reboot_host() {
  print_header
  printf '%s═══ Перезагрузка хоста ═══%s\n\n' "$C_BLD" "$C_RST"

  if [[ -f /var/run/reboot-required ]]; then
    printf '%sРебут запрошен системой.%s\n\n' "$C_YLW" "$C_RST"
    if [[ -f /var/run/reboot-required.pkgs ]]; then
      printf '%sПакеты, ожидающие ребут:%s\n' "$C_BLD" "$C_RST"
      sed 's/^/  • /' /var/run/reboot-required.pkgs
      printf '\n'
      if grep -qE '^linux-image' /var/run/reboot-required.pkgs 2>/dev/null; then
        printf '%s⚠ Среди обновлений ядро.%s Ребут активирует security-фиксы ядра.\n\n' "$C_YLW" "$C_RST"
      fi
    fi
  else
    printf '%s/var/run/reboot-required отсутствует — система не просит ребута.%s\n\n' "$C_GRN" "$C_RST"
  fi

  cat <<INFO
${C_BLD}Что произойдёт при перезагрузке:${C_RST}
  • SSH-сессия (эта) оборвётся
  • Хост уйдёт в reboot, downtime ≈ 30-60 сек
  • После загрузки docker автоматически поднимет remnanode
    (при restart_policy=unless-stopped в /opt/remnanode/docker-compose.yml)
  • chrony, UFW, fail2ban, audit.timer стартанут автоматически
  • Через ~60 сек после загрузки audit.sh продолжит мониторинг

INFO

  if confirm "Перезагрузить хост СЕЙЧАС?" N; then
    printf '\n%sПерезагрузка через 5 сек... (Ctrl+C — отмена)%s\n' "$C_YLW" "$C_RST"
    sleep 5
    systemctl reboot
    # Эта строка обычно не выполняется — SSH сессия уже оборвана
    exit 0
  else
    printf '%sОтменено.%s\n' "$C_DIM" "$C_RST"
    pause
  fi
}

action_uninstall() {
  print_header
  printf '%s═══ ПОЛНОЕ УДАЛЕНИЕ%s\n\n' "$C_RED$C_BLD" "$C_RST"
  printf 'Будет:\n'
  printf '  • остановлены systemd-юниты (audit.timer/daily.timer)\n'
  printf '  • удалены /etc/systemd/system/remnawave-audit*\n'
  printf '  • удалён logrotate-конфиг\n'
  printf '  • %s удалены /etc/remnawave-audit, /var/lib/remnawave-audit, /var/log/remnawave-audit %s\n' "$C_RED" "$C_RST"
  printf '  • удалён симлинк /usr/local/bin/remnawave-audit\n\n'
  printf '%sHardening (UFW/fail2ban/auto-upgrades) НЕ откатывается.%s\n' "$C_YLW" "$C_RST"
  printf '%sСначала используй пункт 12 (откат hardening), если нужно.%s\n\n' "$C_YLW" "$C_RST"
  if confirm "Точно удалить?" N; then
    "${UNINSTALL_SH}" --purge --yes
    printf '\n%sГотово. Папка /opt/remnawave-audit/ осталась — удали вручную если нужно.%s\n' "$C_GRN" "$C_RST"
    pause
    exit 0
  fi
}

# --- Главный цикл ---

main() {
  require_root
  while true; do
    print_header
    print_status_block
    print_menu
    printf '%sВыбор:%s ' "$C_BLD" "$C_RST"
    local choice
    read -r choice </dev/tty || exit 0
    case "$choice" in
      1)  action_diagnose ;;
      2)  action_live_logs ;;
      3)  action_health ;;
      4)  action_systemd_status ;;
      5)  action_test_notify ;;
      6)  action_show_ports ;;
      7)  action_sync_ports ;;
      8)  action_edit_conf ;;
      9)  action_change_tz ;;
      10) action_set_ntp ;;
      11) action_self_update ;;
      12) action_reboot_host ;;
      13) action_rollback ;;
      14) action_uninstall ;;
      0|q|Q|exit|"") clear; exit 0 ;;
      *)  printf '%sНеверный выбор: %s%s\n' "$C_RED" "$choice" "$C_RST"; sleep 1 ;;
    esac
  done
}

main
