#!/usr/bin/env bash
# install.sh — установка remnawave-node-audit на ноду.
#
# Поток:
#   1. Parse args.
#   2. Pre-flight checks (lib/preflight.sh).
#   3. Сбор недостающих параметров (interactive или из флагов).
#   4. Port wizard (lib/ports.sh).
#   5. Создание /etc/remnawave-audit/audit.conf под umask 077.
#   6. Создание /var/lib/remnawave-audit/{queue,backup} и /var/log/remnawave-audit/.
#   7. Hardening: UFW + fail2ban + unattended-upgrades (lib/hardening.sh).
#   8. Установка systemd unit'ов (с подстановкой SCRIPT_DIR / TZ / OnCalendar).
#   9. Установка logrotate.
#  10. Smoke test и финальное сообщение в Telegram.
#
# Идемпотентен: повторный запуск не перезаписывает audit.conf,
# unit'ы и hardening — только обновляет.

set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly LIB_DIR="${SCRIPT_DIR}/lib"
readonly CONFIG_DIR="/etc/remnawave-audit"
readonly CONFIG_PATH="${CONFIG_DIR}/audit.conf"
readonly STATE_DIR="/var/lib/remnawave-audit"
readonly LOG_DIR="/var/log/remnawave-audit"
readonly SYSTEMD_DIR="/etc/systemd/system"
readonly LOGROTATE_FILE="/etc/logrotate.d/remnawave-audit"

# shellcheck source=lib/secrets.sh
. "${LIB_DIR}/secrets.sh"
# shellcheck source=lib/util.sh
. "${LIB_DIR}/util.sh"
# shellcheck source=lib/state.sh
. "${LIB_DIR}/state.sh"
# shellcheck source=lib/ports.sh
. "${LIB_DIR}/ports.sh"
# shellcheck source=lib/preflight.sh
. "${LIB_DIR}/preflight.sh"
# shellcheck source=lib/hardening.sh
. "${LIB_DIR}/hardening.sh"

trap 'on_error $? $LINENO' ERR

# --- args ---
ARG_BOT_TOKEN=""
ARG_ADMIN_ID=""
ARG_NODE_NAME=""
ARG_TZ=""
ARG_NODE_PORT=""
ARG_INBOUND_PORTS=""
ARG_EXTRA_PORTS=""
ARG_SSH_ADMIN_IPS=""
ARG_PROBE_URL=""
ARG_THRESHOLD_CPU=""
ARG_THRESHOLD_RAM=""
ARG_THRESHOLD_DISK=""

OPT_FORCE=0
OPT_UPGRADE=0
OPT_HARDENING_ONLY=0
OPT_SKIP_HARDENING=0
OPT_SKIP_UFW=0
OPT_SKIP_FAIL2BAN=0
OPT_SKIP_UNATTENDED=0
OPT_SKIP_NTP=0
OPT_UFW_RATE_LIMIT=0
OPT_UFW_FORCE_RESET=0
OPT_NON_INTERACTIVE=0
OPT_SET_HOST_TZ=""    # "" = спросить (если интерактив), "1" = да, "0" = не трогать

usage() {
  cat <<'USAGE'
install.sh — установка remnawave-node-audit на ноду.

Использование:
  sudo ./install.sh [options]

Параметры (если не указаны — спросит интерактивно):
  --bot-token=TOKEN          токен Telegram-бота
  --admin-id=ID[,ID...]      chat_id админа(ов), CSV
  --node-name=NAME           человекочитаемое имя ноды
  --tz=TZ                    часовой пояс для дневной сводки (Europe/Moscow)
  --node-port=N              порт связи с панелью (default: из docker-compose.yml)
  --inbound-ports=CSV        порты Xray-инбаундов (default: 443,8388)
  --extra-ports=CSV          дополнительные порты в whitelist
  --ssh-admin-ips=CSV        IP админа — игнорировать в SSH-проверке
  --probe-url=URL            опц. https://<panel>/api/health
  --threshold-cpu=N          порог CPU (default 80)
  --threshold-ram=N          порог RAM (default 85)
  --threshold-disk=N         порог Disk (default 85)

Опции:
  --upgrade                  обновить unit'ы и hardening, не трогать audit.conf
  --hardening-only           только hardening, без audit setup
  --skip-hardening           только audit, без hardening
  --skip-ufw                 не настраивать UFW
  --skip-fail2ban            не настраивать fail2ban
  --skip-unattended          не настраивать unattended-upgrades
  --skip-ntp                 не настраивать NTP (использует свой источник времени)
  --ufw-rate-limit           ufw limit ssh_port/tcp вместо allow
  --ufw-force-reset          разрешить ufw reset при существующих правилах
  --set-host-timezone        выровнять системную TZ хоста под --tz (без вопросов)
  --keep-host-timezone       не трогать системную TZ хоста (даже если интерактив)
  --non-interactive          не задавать вопросов, провалиться если чего-то не хватает
  --force                    пропустить часть pre-flight (например, неподдерживаемая ОС)
  --help, -h                 эта справка

Примеры:
  sudo ./install.sh
  sudo ./install.sh --bot-token=123:AAA --admin-id=12345 --node-name=Finland2 --tz=Europe/Moscow
  sudo ./install.sh --upgrade
  sudo ./install.sh --hardening-only --skip-fail2ban
USAGE
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --bot-token=*)       ARG_BOT_TOKEN="${1#*=}" ;;
      --admin-id=*)        ARG_ADMIN_ID="${1#*=}" ;;
      --node-name=*)       ARG_NODE_NAME="${1#*=}" ;;
      --tz=*)              ARG_TZ="${1#*=}" ;;
      --node-port=*)       ARG_NODE_PORT="${1#*=}" ;;
      --inbound-ports=*)   ARG_INBOUND_PORTS="${1#*=}" ;;
      --extra-ports=*)     ARG_EXTRA_PORTS="${1#*=}" ;;
      --ssh-admin-ips=*)   ARG_SSH_ADMIN_IPS="${1#*=}" ;;
      --probe-url=*)       ARG_PROBE_URL="${1#*=}" ;;
      --threshold-cpu=*)   ARG_THRESHOLD_CPU="${1#*=}" ;;
      --threshold-ram=*)   ARG_THRESHOLD_RAM="${1#*=}" ;;
      --threshold-disk=*)  ARG_THRESHOLD_DISK="${1#*=}" ;;
      --force)             OPT_FORCE=1 ;;
      --upgrade)           OPT_UPGRADE=1 ;;
      --hardening-only)    OPT_HARDENING_ONLY=1 ;;
      --skip-hardening)    OPT_SKIP_HARDENING=1 ;;
      --skip-ufw)          OPT_SKIP_UFW=1 ;;
      --skip-fail2ban)     OPT_SKIP_FAIL2BAN=1 ;;
      --skip-unattended)   OPT_SKIP_UNATTENDED=1 ;;
      --skip-ntp)          OPT_SKIP_NTP=1 ;;
      --ufw-rate-limit)    OPT_UFW_RATE_LIMIT=1 ;;
      --ufw-force-reset)   OPT_UFW_FORCE_RESET=1 ;;
      --set-host-timezone) OPT_SET_HOST_TZ=1 ;;
      --keep-host-timezone) OPT_SET_HOST_TZ=0 ;;
      --non-interactive)   OPT_NON_INTERACTIVE=1 ;;
      -h|--help)           usage; exit 0 ;;
      *)
        log_error "Неизвестный аргумент: $1"
        usage
        exit 1
        ;;
    esac
    shift
  done

  # Валидация совместимости флагов СРАЗУ, до preflight.
  if (( OPT_NON_INTERACTIVE == 1 )) && (( OPT_HARDENING_ONLY == 0 )) && (( OPT_UPGRADE == 0 )); then
    local missing_opts=""
    [[ -z "$ARG_BOT_TOKEN" ]] && missing_opts="${missing_opts}--bot-token "
    [[ -z "$ARG_ADMIN_ID"  ]] && missing_opts="${missing_opts}--admin-id "
    [[ -z "$ARG_NODE_NAME" ]] && missing_opts="${missing_opts}--node-name "
    if [[ -n "$missing_opts" ]]; then
      log_error "--non-interactive: обязательны параметры: ${missing_opts% }"
      exit 1
    fi
  fi
}

# ---------------------------------------------------------------------------
# Сбор параметров
# ---------------------------------------------------------------------------

prompt_or_fail() {
  local var_value="$1" var_name="$2" prompt_text="$3" default="${4:-}"
  if [[ -n "$var_value" ]]; then
    printf '%s' "$var_value"
    return
  fi
  if (( OPT_NON_INTERACTIVE == 1 )); then
    log_error "${var_name} не передан, а режим --non-interactive"
    exit 1
  fi
  local input
  if [[ -n "$default" ]]; then
    printf '%s [%s]: ' "$prompt_text" "$default" >&2
  else
    printf '%s: ' "$prompt_text" >&2
  fi
  read -r input </dev/tty
  printf '%s' "${input:-$default}"
}

prompt_secret_or_fail() {
  local var_value="$1" var_name="$2" prompt_text="$3"
  if [[ -n "$var_value" ]]; then
    printf '%s' "$var_value"
    return
  fi
  if (( OPT_NON_INTERACTIVE == 1 )); then
    log_error "${var_name} не передан, а режим --non-interactive"
    exit 1
  fi
  local input
  printf '%s: ' "$prompt_text" >&2
  read -r -s input </dev/tty
  printf '\n' >&2
  printf '%s' "$input"
}

collect_telegram() {
  BOT_TOKEN="$(prompt_secret_or_fail "$ARG_BOT_TOKEN" BOT_TOKEN \
    "BOT_TOKEN (токен бота от @BotFather)")"
  if [[ ! "$BOT_TOKEN" =~ ^[0-9]+:[A-Za-z0-9_-]{30,}$ ]]; then
    log_error "BOT_TOKEN формат: <digits>:<>=30 base64-ish>"
    exit 1
  fi
  secrets_register "$BOT_TOKEN"

  ADMIN_CHAT_ID="$(prompt_or_fail "$ARG_ADMIN_ID" ADMIN_CHAT_ID \
    "ADMIN_CHAT_ID (CSV — например 12345 или -1001234567890)")"
  if [[ ! "$ADMIN_CHAT_ID" =~ ^(-?[0-9]+,?)+$ ]]; then
    log_error "ADMIN_CHAT_ID формат: CSV целых чисел"
    exit 1
  fi
}

collect_node_meta() {
  NODE_NAME="$(prompt_or_fail "$ARG_NODE_NAME" NODE_NAME \
    "NODE_NAME (например Finland2)")"
  [[ -z "$NODE_NAME" ]] && { log_error "NODE_NAME пустой"; exit 1; }

  local sys_tz
  sys_tz="$(timedatectl show -p Timezone --value 2>/dev/null || echo UTC)"
  TZ_VALUE="$(prompt_or_fail "$ARG_TZ" TZ "TZ для дневной сводки" "$sys_tz")"
  if [[ ! -e "/usr/share/zoneinfo/${TZ_VALUE}" ]]; then
    log_error "TZ='${TZ_VALUE}' не найдено в /usr/share/zoneinfo. Используй 'timedatectl list-timezones'."
    exit 1
  fi

  # Авто-синхронизация системной TZ хоста с TZ_VALUE.
  # Иначе timestamps в journalctl/date будут UTC, а сообщения скрипта — MSK
  # (или наоборот), что путает.
  if [[ "$sys_tz" != "$TZ_VALUE" ]]; then
    local apply=0
    case "${OPT_SET_HOST_TZ}" in
      1)  apply=1 ;;
      0)  apply=0 ;;
      "")
        if (( OPT_NON_INTERACTIVE == 1 )); then
          apply=0
          log_info "Системная TZ хоста (${sys_tz}) ≠ ${TZ_VALUE}, --non-interactive → не трогаю. Передай --set-host-timezone чтобы выровнять."
        else
          local ans
          printf '\nСистемная TZ хоста: %s\n' "$sys_tz" >&2
          printf 'TZ для скрипта:     %s\n' "$TZ_VALUE" >&2
          printf 'Выровнять системную TZ под %s (timedatectl set-timezone)? [Y/n]: ' "$TZ_VALUE" >&2
          read -r ans </dev/tty
          [[ "$ans" != "n" && "$ans" != "N" ]] && apply=1
        fi
        ;;
    esac
    if (( apply == 1 )); then
      timedatectl set-timezone "$TZ_VALUE"
      log_info "Системная TZ хоста: ${sys_tz} → ${TZ_VALUE}"
    fi
  fi
}

collect_ports() {
  if [[ -n "$ARG_NODE_PORT" && -n "$ARG_INBOUND_PORTS" ]]; then
    NODE_PORT="$ARG_NODE_PORT"
    INBOUND_PORTS="$ARG_INBOUND_PORTS"
  elif (( OPT_NON_INTERACTIVE == 1 )); then
    NODE_PORT="${ARG_NODE_PORT:-$(ports_compose_node_port)}"
    NODE_PORT="${NODE_PORT:-2222}"
    INBOUND_PORTS="${ARG_INBOUND_PORTS:-443,8388}"
  else
    if ! ports_wizard </dev/tty; then
      log_error "Port wizard отменён"
      exit 1
    fi
    NODE_PORT="$WIZARD_NODE_PORT"
    INBOUND_PORTS="$WIZARD_INBOUND_PORTS"
  fi
  EXTRA_PORTS_WHITELIST="${ARG_EXTRA_PORTS:-}"
}

collect_thresholds() {
  THRESHOLD_CPU="${ARG_THRESHOLD_CPU:-80}"
  THRESHOLD_RAM="${ARG_THRESHOLD_RAM:-85}"
  THRESHOLD_DISK="${ARG_THRESHOLD_DISK:-85}"
  SSH_ADMIN_IPS="${ARG_SSH_ADMIN_IPS:-}"
  EXTERNAL_PROBE_URL="${ARG_PROBE_URL:-}"
}

# ---------------------------------------------------------------------------
# Запись audit.conf
# ---------------------------------------------------------------------------

write_audit_conf() {
  if [[ -f "$CONFIG_PATH" ]]; then
    log_info "audit.conf уже существует — оставляю как есть. Для перезаписи удали файл вручную."
    return 0
  fi
  mkdir -p "$CONFIG_DIR"
  chmod 700 "$CONFIG_DIR"

  local tmp
  umask 077
  tmp="$(mktemp "${CONFIG_PATH}.tmp.XXXXXX")"
  {
    printf '# Generated by install.sh on %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf '# Mode 600, owner root. НЕ коммитить.\n\n'
    printf '# --- Telegram ---\n'
    printf 'BOT_TOKEN=%s\n' "$(printf '%q' "$BOT_TOKEN")"
    printf 'ADMIN_CHAT_ID=%s\n\n' "$(printf '%q' "$ADMIN_CHAT_ID")"
    printf '# --- Идентификация ноды ---\n'
    printf 'NODE_NAME=%s\n' "$(printf '%q' "$NODE_NAME")"
    printf 'TZ=%s\n\n' "$(printf '%q' "$TZ_VALUE")"
    printf '# --- Порты ---\n'
    printf 'NODE_PORT=%s\n' "$NODE_PORT"
    printf 'INBOUND_PORTS=%s\n' "$INBOUND_PORTS"
    printf 'EXTRA_PORTS_WHITELIST=%s\n\n' "$EXTRA_PORTS_WHITELIST"
    printf '# --- Безопасность ---\n'
    printf 'SSH_ADMIN_IPS=%s\n\n' "$SSH_ADMIN_IPS"
    printf '# --- Пороги ---\n'
    printf 'THRESHOLD_CPU=%s\n'  "$THRESHOLD_CPU"
    printf 'THRESHOLD_RAM=%s\n'  "$THRESHOLD_RAM"
    printf 'THRESHOLD_DISK=%s\n\n' "$THRESHOLD_DISK"
    printf '# --- Cooldown ---\n'
    printf 'COOLDOWN_CRITICAL_SEC=900\n'
    printf 'COOLDOWN_WARNING_SEC=3600\n\n'
    printf '# --- Опц. ---\n'
    printf 'EXTERNAL_PROBE_URL=%s\n' "$(printf '%q' "$EXTERNAL_PROBE_URL")"
  } > "$tmp"
  mv "$tmp" "$CONFIG_PATH"
  chmod 600 "$CONFIG_PATH"
  chown root:root "$CONFIG_PATH"
  log_info "audit.conf создан: ${CONFIG_PATH}"
}

prepare_dirs() {
  mkdir -p "$STATE_DIR/queue" "$STATE_DIR/backup" "$LOG_DIR"
  chmod 700 "$STATE_DIR"
  chmod 750 "$LOG_DIR"
}

# Ставит jq/curl/ca-certificates до preflight, чтобы preflight_check_required_cmds
# не падал на свежей Ubuntu (jq не предустановлен в 22.04/24.04 default).
ensure_base_packages() {
  is_root || return 0
  local need=() pkg
  for pkg in jq curl ca-certificates; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
      need+=("$pkg")
    fi
  done
  if (( ${#need[@]} == 0 )); then
    return 0
  fi
  log_info "Устанавливаю базовые зависимости: ${need[*]}"
  DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1 || \
    log_warn "apt-get update вернул ошибку — возможно проблема с сетью/репозиториями"
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${need[@]}" >/dev/null
}

# ---------------------------------------------------------------------------
# systemd / logrotate
# ---------------------------------------------------------------------------

# Только копирование unit-файлов и daemon-reload. Без enable --now!
# Таймеры включаются ПОСЛЕ smoke-test (enable_systemd_timers), чтобы
# не было race condition на /run/remnawave-audit.lock.
install_systemd_units() {
  log_info "systemd: daily timer на 08:00 в TZ=${TZ_VALUE:-UTC} (через OnCalendar TZ-suffix, DST-safe)"

  local src dst tmp
  for unit in remnawave-audit.service remnawave-audit.timer \
              remnawave-audit-daily.service remnawave-audit-daily.timer; do
    src="${SCRIPT_DIR}/systemd/${unit}"
    dst="${SYSTEMD_DIR}/${unit}"
    [[ -f "$src" ]] || { log_error "Не найден: ${src}"; exit 1; }
    tmp="$(mktemp "${dst}.tmp.XXXXXX")"
    sed -e "s|__SCRIPT_DIR__|${SCRIPT_DIR}|g" \
        -e "s|__TZ__|${TZ_VALUE:-UTC}|g" \
        "$src" > "$tmp"
    mv "$tmp" "$dst"
    chmod 644 "$dst"
  done

  systemctl daemon-reload
  log_info "systemd: unit-файлы установлены, daemon-reload выполнен"
}

enable_systemd_timers() {
  systemctl enable --now remnawave-audit.timer >/dev/null
  systemctl enable --now remnawave-audit-daily.timer >/dev/null
  log_info "systemd: enabled remnawave-audit.timer (2 мин) + remnawave-audit-daily.timer (08:00 ${TZ_VALUE:-UTC})"
}

install_logrotate() {
  local src="${SCRIPT_DIR}/logrotate/remnawave-audit"
  [[ -f "$src" ]] || { log_warn "logrotate-конфиг не найден: ${src}"; return 0; }
  cp "$src" "$LOGROTATE_FILE"
  chmod 644 "$LOGROTATE_FILE"
  log_info "logrotate: ${LOGROTATE_FILE}"
}

install_cli_symlink() {
  local target="/usr/local/bin/remnawave-audit"
  # Симлинк на menu.sh: без аргументов открывает интерактивное меню,
  # с аргументами — прозрачно пробрасывает в audit.sh.
  ln -sf "${SCRIPT_DIR}/menu.sh" "$target"
  log_info "CLI: 'sudo remnawave-audit' — меню; 'sudo remnawave-audit --diagnose' — прямой вызов"
}

# ---------------------------------------------------------------------------
# Smoke test и финальный нотиф
# ---------------------------------------------------------------------------

smoke_test() {
  log_info "Smoke test: audit.sh --test-notify"
  if "${SCRIPT_DIR}/audit.sh" --test-notify; then
    log_info "test-notify: ОК"
  else
    log_warn "test-notify: не удалось (см. journalctl или /var/log/remnawave-audit/alerts.log)"
  fi

  log_info "Smoke test: audit.sh --once"
  local rc=0
  "${SCRIPT_DIR}/audit.sh" --once || rc=$?
  case "$rc" in
    0) log_info "audit --once: всё ОК" ;;
    1) log_info "audit --once: warning'и есть (это норм при первой установке)" ;;
    2) log_warn "audit --once: есть critical-проверки — проверь /var/log/remnawave-audit/alerts.log" ;;
    *) log_warn "audit --once: exit code ${rc}" ;;
  esac
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  parse_args "$@"

  if (( OPT_UPGRADE == 1 )); then
    log_info "=== Upgrade mode: только unit'ы и hardening, конфиг не трогаем ==="
    if [[ ! -f "$CONFIG_PATH" ]]; then
      log_error "${CONFIG_PATH} не существует — нечего upgrade'ить. Сначала install."
      exit 1
    fi
    # shellcheck disable=SC1090
    . "$CONFIG_PATH"
    TZ_VALUE="${TZ:-UTC}"
    install_systemd_units
    enable_systemd_timers
    install_logrotate
    install_cli_symlink
    if (( OPT_SKIP_HARDENING == 0 )); then
      local hf=()
      (( OPT_SKIP_UFW == 1 ))         && hf+=(--skip-ufw)
      (( OPT_SKIP_FAIL2BAN == 1 ))    && hf+=(--skip-fail2ban)
      (( OPT_SKIP_UNATTENDED == 1 ))  && hf+=(--skip-unattended)
      (( OPT_SKIP_NTP == 1 ))         && hf+=(--skip-ntp)
      (( OPT_UFW_RATE_LIMIT == 1 ))   && hf+=(--ufw-rate-limit)
      (( OPT_UFW_FORCE_RESET == 1 ))  && export HARDENING_UFW_FORCE_RESET=1
      hardening_run "${hf[@]}"
    fi
    log_info "Upgrade завершён."
    return 0
  fi

  # Базовые пакеты — до preflight (иначе jq отсутствует и preflight фейлит).
  ensure_base_packages

  # Pre-flight (с токеном если он передан флагом — иначе позже)
  local pf_args=()
  (( OPT_FORCE == 1 )) && pf_args+=(--force)
  [[ -n "$ARG_BOT_TOKEN" ]] && pf_args+=(--bot-token="$ARG_BOT_TOKEN")
  if ! preflight_run "${pf_args[@]}"; then
    exit 1
  fi

  if (( OPT_HARDENING_ONLY == 0 )); then
    if [[ -f "$CONFIG_PATH" ]]; then
      # Resumable install: подхватываем существующий audit.conf без вопросов.
      # Нужно если предыдущий запуск упал на hardening (например, UFW reset).
      log_info "audit.conf уже существует — продолжаю с существующих значений"
      log_info "(чтобы пересоздать конфиг — удали ${CONFIG_PATH} и запусти install заново)"
      # shellcheck disable=SC1090
      . "$CONFIG_PATH"
      TZ_VALUE="${TZ:-UTC}"
      secrets_register "${BOT_TOKEN:-}"
    else
      collect_telegram
      collect_node_meta
      collect_ports
      collect_thresholds
      write_audit_conf
    fi
    prepare_dirs
  else
    log_info "=== Hardening-only mode: пропускаю audit setup ==="
    if [[ -f "$CONFIG_PATH" ]]; then
      # shellcheck disable=SC1090
      . "$CONFIG_PATH"
      TZ_VALUE="${TZ:-UTC}"
    fi
  fi

  if (( OPT_SKIP_HARDENING == 0 )); then
    local hf=()
    (( OPT_SKIP_UFW == 1 ))         && hf+=(--skip-ufw)
    (( OPT_SKIP_FAIL2BAN == 1 ))    && hf+=(--skip-fail2ban)
    (( OPT_SKIP_UNATTENDED == 1 ))  && hf+=(--skip-unattended)
    (( OPT_UFW_RATE_LIMIT == 1 ))   && hf+=(--ufw-rate-limit)
    (( OPT_UFW_FORCE_RESET == 1 ))  && export HARDENING_UFW_FORCE_RESET=1
    hardening_run "${hf[@]}"
  else
    log_info "Hardening пропущен (--skip-hardening)"
  fi

  if (( OPT_HARDENING_ONLY == 0 )); then
    install_systemd_units
    install_logrotate
    install_cli_symlink
    smoke_test
    # Таймеры включаются ПОСЛЕ smoke-test, иначе первый прогон таймера
    # пересекается с smoke-test'овым `audit.sh --once` на /run/.../lock.
    enable_systemd_timers
  fi

  printf '\n=== Установка завершена ===\n'
  printf 'Меню:             sudo remnawave-audit\n'
  printf 'Конфиг:           %s\n' "$CONFIG_PATH"
  printf 'Состояние:        %s\n' "$STATE_DIR"
  printf 'Логи:             %s\n' "$LOG_DIR"
  printf 'systemd:          systemctl status remnawave-audit.timer\n'
  printf 'Ручной прогон:    sudo remnawave-audit --diagnose\n'
  printf 'Откат hardening:  sudo remnawave-audit --rollback\n'
}

main "$@"
