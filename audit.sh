#!/usr/bin/env bash
# audit.sh — Remnawave node audit + Telegram notifier.
# Точка входа: парсит флаги, грузит конфиг, держит lock, диспатчит проверки.

set -Eeuo pipefail
IFS=$'\n\t'

readonly VERSION="1.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly LIB_DIR="${SCRIPT_DIR}/lib"
readonly CONFIG_PATH="${REMNAWAVE_AUDIT_CONFIG:-/etc/remnawave-audit/audit.conf}"
readonly STATE_DIR="/var/lib/remnawave-audit"
readonly LOG_DIR="/var/log/remnawave-audit"
readonly LOCK_FILE="/run/remnawave-audit.lock"
readonly LOCK_FILE_FALLBACK="/var/run/remnawave-audit.lock"

# shellcheck source=lib/secrets.sh
. "${LIB_DIR}/secrets.sh"
# shellcheck source=lib/util.sh
. "${LIB_DIR}/util.sh"
# shellcheck source=lib/state.sh
. "${LIB_DIR}/state.sh"
# shellcheck source=lib/checks.sh
. "${LIB_DIR}/checks.sh"
# shellcheck source=lib/ports.sh
. "${LIB_DIR}/ports.sh"
# shellcheck source=lib/notify.sh
. "${LIB_DIR}/notify.sh"
# shellcheck source=lib/hardening.sh
. "${LIB_DIR}/hardening.sh"

trap 'on_error $? $LINENO' ERR
trap 'on_exit' EXIT

DRY_RUN=0
ONCE=0
export DEBUG=0  # читается в lib/util.sh::log_debug — export подавляет SC2034
ACTION="run"
EXIT_CODE=0
AUTO_RECOVER_FLAG=0
ASSUME_YES=0

usage() {
  cat <<'USAGE'
audit.sh — Remnawave node audit + Telegram notifier

Использование:
  audit.sh [--once] [--dry-run] [--debug] [--auto-recover]
  audit.sh --daily-summary
  audit.sh --test-notify
  audit.sh --test-alert        # симуляция алертов для проверки pipeline
  audit.sh --diagnose
  audit.sh --show-ports
  audit.sh --sync-ports
  audit.sh --health
  audit.sh --self-update
  audit.sh --rollback [--yes]
  audit.sh --version
  audit.sh --help

Exit codes (для --once):
  0  всё ок
  1  есть warning
  2  есть critical
  3  скрипт сам сломан (конфиг, отсутствует утилита, и т.д.)

Конфиг: /etc/remnawave-audit/audit.conf (mode 600).
USAGE
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --once)         ONCE=1 ;;
      --dry-run)      DRY_RUN=1 ;;
      --debug)        DEBUG=1 ;;
      --test-notify)  ACTION="test_notify" ;;
      --diagnose)     ACTION="diagnose" ;;
      --show-ports)   ACTION="show_ports" ;;
      --sync-ports)   ACTION="sync_ports" ;;
      --health)       ACTION="health" ;;
      --self-update)  ACTION="self_update" ;;
      --rollback)     ACTION="rollback" ;;
      --daily-summary) ACTION="daily_summary" ;;
      --test-alert)   ACTION="test_alert" ;;
      --auto-recover) AUTO_RECOVER_FLAG=1 ;;
      --yes|-y)       ASSUME_YES=1 ;;
      --version)      printf 'audit.sh %s\n' "$VERSION"; exit 0 ;;
      -h|--help)      usage; exit 0 ;;
      *)              log_error "Unknown argument: $1"; usage; exit 3 ;;
    esac
    shift
  done
}

acquire_lock() {
  local lock_path="$LOCK_FILE"
  [[ -d /run ]] || lock_path="$LOCK_FILE_FALLBACK"
  exec 9>"$lock_path"
  chmod 600 "$lock_path" 2>/dev/null || true
  if ! flock -n 9; then
    log_error "Another instance is running (lock: $lock_path)"
    exit 3
  fi
}

load_config() {
  if [[ ! -f "$CONFIG_PATH" ]]; then
    log_error "Config not found: $CONFIG_PATH (run install.sh first)"
    exit 3
  fi
  # shellcheck disable=SC1090
  . "$CONFIG_PATH"
  validate_config
}

validate_config() {
  : "${BOT_TOKEN:?BOT_TOKEN is required}"
  : "${ADMIN_CHAT_ID:?ADMIN_CHAT_ID is required}"
  : "${NODE_NAME:?NODE_NAME is required}"
  if [[ ! "$BOT_TOKEN" =~ ^[0-9]+:[A-Za-z0-9_-]{30,}$ ]]; then
    log_error "BOT_TOKEN format invalid"
    exit 3
  fi
  if [[ ! "$ADMIN_CHAT_ID" =~ ^(-?[0-9]+,?)+$ ]]; then
    log_error "ADMIN_CHAT_ID format invalid (expecting CSV of integers)"
    exit 3
  fi
  secrets_register "$BOT_TOKEN"
  # SECRET_KEY обычно не в audit.conf, а в env контейнера remnanode
  # (читаем через docker inspect в check_certs). Но если кто-то его сюда
  # положит вручную — замаскируем в логах.
  # NB: if-форма обязательна — `cond && cmd` на последней строке функции
  # возвращает 1 при false условии, что под set -e убивает скрипт.
  if [[ -n "${SECRET_KEY:-}" ]]; then
    secrets_register "$SECRET_KEY"
  fi
}

# Запуск всех checks_*, агрегация по severity, отправка через notify,
# запись health-данных в state, опц. auto-recover.
run_checks_and_dispatch() {
  local results
  results="$(checks_run_all)"

  local n_crit=0 n_warn=0
  while IFS='|' read -r sev _key _msg _details; do
    [[ -z "$sev" ]] && continue
    case "$sev" in
      CRIT) n_crit=$((n_crit+1)) ;;
      WARN) n_warn=$((n_warn+1)) ;;
    esac
  done <<<"$results"

  notify_dispatch_results "$results"

  state_set "last_run_unix" "$(date +%s)"
  state_set "last_run_n_crit" "$n_crit"
  state_set "last_run_n_warn" "$n_warn"
  if (( n_crit > 0 )); then
    state_set "last_run_status" "critical"
    EXIT_CODE=2
  elif (( n_warn > 0 )); then
    state_set "last_run_status" "warning"
    EXIT_CODE=1
  else
    state_set "last_run_status" "ok"
  fi

  log_info "checks done: critical=${n_crit} warning=${n_warn}"

  if [[ "${AUTO_RECOVER_FLAG}" == "1" || "${AUTO_RECOVER:-0}" == "1" ]]; then
    auto_recover_if_needed "$results"
  fi
}

# auto_recover_if_needed <results>
# Если в results есть CRIT container_status и не превышен rate limit,
# пытается выполнить `docker compose up -d` для remnanode. Max 3 раза в час.
auto_recover_if_needed() {
  local results="$1"
  if ! printf '%s' "$results" | grep -qE '^CRIT\|container_(status|missing|unhealthy)'; then
    return 0
  fi

  local now window count
  now="$(date +%s)"
  window="$(state_get_int auto_recover_window_start 0)"
  count="$(state_get_int auto_recover_count 0)"
  if (( now - window > 3600 )); then
    state_set auto_recover_window_start "$now"
    state_set auto_recover_count "0"
    count=0
  fi
  if (( count >= 3 )); then
    log_warn "auto-recover: rate limit hit (${count}/3 за час) — пропуск"
    return 0
  fi
  state_set auto_recover_count "$((count+1))"

  log_info "auto-recover: docker compose up -d (попытка #$((count+1))/3)"
  local out rc=0
  out="$(cd /opt/remnanode 2>/dev/null && timeout 60 docker compose up -d 2>&1)" || rc=$?
  if (( rc == 0 )); then
    log_info "auto-recover: docker compose up успешно"
  else
    log_warn "auto-recover: docker compose up failed (rc=${rc})"
    log_debug "${out}"
  fi
}

# --diagnose: запускает все проверки, печатает в stdout (включая OK),
# state не модифицируется, в Telegram НЕ отправляет ничего.
run_diagnose() {
  # shellcheck disable=SC2034  # читается в lib/state.sh — отключает запись в state
  STATE_READONLY=1
  local results
  results="$(checks_run_all)"
  while IFS='|' read -r sev key msg details; do
    [[ -z "$sev" ]] && continue
    details="${details//$'\x01'/$'\n    '}"
    case "$sev" in
      CRIT) printf '🔴 [%s] %s\n    %s\n' "$key" "$msg" "${details:-}" ;;
      WARN) printf '🟡 [%s] %s\n    %s\n' "$key" "$msg" "${details:-}" ;;
      INFO) printf '🟢 [%s] %s\n    %s\n' "$key" "$msg" "${details:-}" ;;
      OK)   printf '✓  [%s] %s\n' "$key" "$msg" ;;
    esac
  done <<<"$results"
  EXIT_CODE=0
}

# --health: печатает JSON со статусом последнего прогона. Для внешнего watchdog.
action_health() {
  # shellcheck disable=SC2034  # читается в lib/state.sh — отключает запись в state
  STATE_READONLY=1
  local last_run last_status n_crit n_warn active queue ts ufw f2b uu
  last_run="$(state_get_int "last_run_unix" 0)"
  last_status="$(state_get "last_run_status" "unknown")"
  n_crit="$(state_get_int "last_run_n_crit" 0)"
  n_warn="$(state_get_int "last_run_n_warn" 0)"
  active="$(state_get "notified_keys" "")"
  queue="$(find "${STATE_DIR}/queue" -maxdepth 1 -type f -name '*.json' 2>/dev/null | wc -l)"
  ts="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  ufw="$(state_get "hardening_ufw_managed" "no")"
  f2b="$(state_get "hardening_fail2ban_managed" "no")"
  uu="$(state_get "hardening_unattended_managed" "no")"

  jq -nc \
    --arg ts "$ts" \
    --arg version "$VERSION" \
    --arg node "${NODE_NAME:-}" \
    --arg lru "$last_run" \
    --arg lst "$last_status" \
    --arg nc "$n_crit" \
    --arg nw "$n_warn" \
    --arg act "$active" \
    --arg qd "$queue" \
    --arg ufw "$ufw" --arg f2b "$f2b" --arg uu "$uu" '
    {
      ts: $ts,
      version: $version,
      node: $node,
      last_run: { unix: ($lru | tonumber), status: $lst, critical: ($nc | tonumber), warning: ($nw | tonumber) },
      active_alerts: ($act | split(",") | map(select(. != ""))),
      queue_depth: ($qd | tonumber),
      hardening: { ufw: $ufw, fail2ban: $f2b, unattended_upgrades: $uu }
    }'
  EXIT_CODE=0
}

# --self-update: git pull --ff-only + install.sh --upgrade при изменении unit'ов.
action_self_update() {
  is_root || { log_error "--self-update требует root"; EXIT_CODE=1; return; }

  if [[ ! -d "${SCRIPT_DIR}/.git" ]]; then
    log_error "${SCRIPT_DIR} не является git-репо. Self-update недоступен."
    EXIT_CODE=1; return
  fi

  if [[ -n "$(git -C "$SCRIPT_DIR" status --porcelain)" ]]; then
    log_error "В ${SCRIPT_DIR} есть локальные изменения — abort. Сначала: git -C ${SCRIPT_DIR} status"
    EXIT_CODE=1; return
  fi

  local before after
  before="$(git -C "$SCRIPT_DIR" rev-parse HEAD)"
  if ! git -C "$SCRIPT_DIR" pull --ff-only --quiet; then
    log_error "git pull --ff-only failed"
    EXIT_CODE=1; return
  fi
  after="$(git -C "$SCRIPT_DIR" rev-parse HEAD)"

  if [[ "$before" == "$after" ]]; then
    log_info "Уже на последней версии: ${after:0:12}"
    return
  fi
  log_info "Update: ${before:0:12} → ${after:0:12}"

  local changed
  changed="$(git -C "$SCRIPT_DIR" diff --name-only "$before" "$after")"

  if printf '%s' "$changed" | grep -qE '^(systemd/|install\.sh$)'; then
    log_info "Изменились unit'ы или install.sh — запускаю install.sh --upgrade"
    "${SCRIPT_DIR}/install.sh" --upgrade --skip-hardening || \
      log_warn "install.sh --upgrade завершился с ошибкой (exit ${?})"
  fi

  if printf '%s' "$changed" | grep -qE '^lib/hardening\.sh$'; then
    log_warn "lib/hardening.sh изменился, но self-update не применил (--skip-hardening)."
    log_warn "Чтобы применить — запусти: sudo ${SCRIPT_DIR}/install.sh --hardening-only"
    _notify_emit INFO hardening_update_pending \
      "lib/hardening.sh обновился — нужен ручной запуск install.sh --hardening-only" \
      "self-update не применяет hardening автоматически (риск отрезать SSH)"
  fi

  if printf '%s' "$changed" | grep -qE '^audit\.conf\.example$'; then
    local diff_text
    diff_text="$(git -C "$SCRIPT_DIR" diff "$before" "$after" -- audit.conf.example | head -60)"
    _notify_emit INFO config_example_changed \
      "audit.conf.example обновлён — обнови /etc/remnawave-audit/audit.conf вручную" \
      "$diff_text"
  fi

  log_info "Self-update завершён: ${after:0:12}"
}

# --test-alert: симулирует алерты для тестирования. НЕ ТРОГАЕТ систему.
# Шлёт по одному примеру каждого severity в Telegram, чтобы убедиться что:
#   - формат сообщений правильный
#   - заголовок [NODE_NAME / IP] подставляется
#   - HTML-escape работает
#   - все 4 severity (CRIT/WARN/INFO/RECOVERY) проходят
action_test_alert() {
  notify_init

  log_info "Симуляция алертов: посылаю по одному CRIT/WARN/INFO/RECOVERY"

  # Используем _notify_emit (минуя cooldown и notified_keys) — это фейк-сообщения,
  # они не должны влиять на реальные алерты.
  _notify_emit CRIT "test_alert_crit" \
    "🧪 ТЕСТ: симуляция CRITICAL алерта" \
    "Это тестовое сообщение от audit.sh --test-alert.
Если вы видите его в Telegram — pipeline работает.
Реальный CRIT приходит при: контейнер упал / порт не слушает / диск >95% / NTP не synced."

  sleep 2

  _notify_emit WARN "test_alert_warn" \
    "🧪 ТЕСТ: симуляция WARNING алерта" \
    "Это тестовое сообщение.
WARN приходит при: CPU >80% / диск >85% / новый порт / SSH brute / устаревший образ."

  sleep 2

  _notify_emit INFO "test_alert_info" \
    "🧪 ТЕСТ: симуляция INFO алерта" \
    "Это тестовое сообщение.
INFO — для дневных сводок, ротации SECRET_KEY, доступных обновлений."

  sleep 2

  _notify_emit RECOVERY "test_alert_recovery" \
    "🧪 ТЕСТ: симуляция RECOVERY алерта" \
    "Это тестовое сообщение.
RECOVERY приходит когда CRIT/WARN исчезают на 3+ цикла подряд (~6 минут стабильности)."

  log_info "test-alert: 4 сообщения отправлены (CRIT/WARN/INFO/RECOVERY)"
  log_info "Если в Telegram пришли все 4 — pipeline алертов работает корректно."
  EXIT_CODE=0
}

# --daily-summary: дневная сводка раз в сутки в 08:00 (по TZ из конфига).
action_daily_summary() {
  notify_init

  local ip uptime_h started uptime_c restarts sess_443 sess_8388
  local disk_pct ram_pct la cert_days reboot_req
  local ufw_st f2b_st uu_st crit_24h warn_24h since
  ip="$(state_get "network_external_ip" "?")"

  # Uptime контейнера
  started="$(timeout 5 docker inspect "${REMNANODE_CONTAINER:-remnanode}" \
              --format '{{.State.StartedAt}}' 2>/dev/null)"
  if [[ -n "$started" ]]; then
    local started_unix now_unix up
    started_unix="$(date -d "$started" +%s 2>/dev/null || echo 0)"
    now_unix="$(date +%s)"
    up=$(( now_unix - started_unix ))
    if (( up > 0 )); then
      uptime_c="$(printf '%dд %dч %02dм' $((up/86400)) $(((up%86400)/3600)) $(((up%3600)/60)))"
    else
      uptime_c="?"
    fi
  else
    uptime_c="(контейнер не найден)"
  fi

  # Uptime хоста
  uptime_h="$(awk '{u=int($1); printf "%dд %dч", u/86400, (u%86400)/3600}' /proc/uptime)"

  restarts="$(state_get_int container_restart_count 0)"

  # Сессии
  sess_443="$(ss -tn '( sport = :443 )' 2>/dev/null | tail -n +2 | wc -l)"
  sess_8388="$(ss -tn '( sport = :8388 )' 2>/dev/null | tail -n +2 | wc -l)"

  # Disk / RAM / LA
  disk_pct="$(df -P / 2>/dev/null | awk 'NR==2 {print $5}')"
  ram_pct="$(awk '/MemAvailable:/{a=$2} /MemTotal:/{t=$2} END{if(t>0) printf "%.0f%%", 100*(t-a)/t}' /proc/meminfo)"
  la="$(awk '{print $1}' /proc/loadavg)"

  # Сертификат — используем кеш
  cert_days="$(state_get "cert_node_days_left" "?")"

  reboot_req="$([[ -f /var/run/reboot-required ]] && echo да || echo нет)"

  ufw_st="$(state_get "hardening_ufw_managed" "—")"
  f2b_st="$(state_get "hardening_fail2ban_managed" "—")"
  uu_st="$(state_get "hardening_unattended_managed" "—")"

  # Проверка обновления образа — только в daily (docker manifest имеет rate-limit Docker Hub)
  local image_status="?"
  if command -v docker >/dev/null 2>&1; then
    local remote local_img
    remote="$(timeout 10 docker manifest inspect "${REMNANODE_IMAGE:-remnawave/node:latest}" 2>/dev/null \
                | jq -r '.config.digest // .manifests[0].digest // empty' 2>/dev/null)"
    local_img="$(timeout 5 docker inspect "${REMNANODE_CONTAINER:-remnanode}" \
                  --format '{{.Image}}' 2>/dev/null)"
    if [[ -n "$remote" && -n "$local_img" ]]; then
      if [[ "$remote" == "$local_img" ]]; then
        image_status="актуален (${local_img:7:12}…)"
      else
        image_status="⚠ доступно обновление: ${local_img:7:12}… → ${remote:7:12}…"
      fi
    fi
  fi

  # Инциденты за 24 часа из alerts.log
  since="$(date -u -d '24 hours ago' '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null)"
  if [[ -f "${LOG_DIR}/alerts.log" && -n "$since" ]]; then
    crit_24h="$(jq -c --arg s "$since" 'select(.ts > $s and .sev == "CRIT")' \
                "${LOG_DIR}/alerts.log" 2>/dev/null | wc -l)"
    warn_24h="$(jq -c --arg s "$since" 'select(.ts > $s and .sev == "WARN")' \
                "${LOG_DIR}/alerts.log" 2>/dev/null | wc -l)"
  else
    crit_24h=0; warn_24h=0
  fi

  local body
  body="$(cat <<EOF
Контейнер remnanode: running ${uptime_c}, рестартов: ${restarts}
Внешний IP: ${ip}
Сессий: :443=${sess_443}, :8388=${sess_8388}
Диск /: ${disk_pct} | RAM: ${ram_pct:-?} | LA: ${la}
Сертификат ноды: ${cert_days} дн. до истечения
Образ: ${image_status}
Хост uptime: ${uptime_h}
UFW: ${ufw_st} | fail2ban: ${f2b_st} | auto-upgrades: ${uu_st}
Инцидентов за сутки: ${crit_24h} critical, ${warn_24h} warning
Перезагрузка хоста требуется: ${reboot_req}
Версия скрипта: ${VERSION}
EOF
)"

  _notify_emit INFO daily_summary "Сводка за сутки" "$body"
  state_set "last_daily_summary_unix" "$(date +%s)"
  log_info "daily summary отправлено"
}

main() {
  parse_args "$@"

  # Lock берём только для actions которые пишут state/queue или меняют систему.
  # Read-only actions (--diagnose/--show-ports/--health) не должны блокировать
  # systemd-таймер с его прогонами --once.
  case "$ACTION" in
    diagnose|show_ports|health|version) : ;;  # read-only, без lock
    *) acquire_lock ;;
  esac

  load_config

  log_info "audit.sh ${VERSION} action=${ACTION} dry_run=${DRY_RUN} once=${ONCE}"

  case "$ACTION" in
    run)
      run_checks_and_dispatch
      ;;
    test_notify)
      notify_test_message || EXIT_CODE=1
      ;;
    diagnose)
      run_diagnose
      ;;
    show_ports)
      ports_show_table
      ;;
    sync_ports)
      ports_sync_interactive || EXIT_CODE=1
      ;;
    health)
      action_health
      ;;
    self_update)
      action_self_update
      ;;
    rollback)
      if (( ASSUME_YES == 1 )); then
        hardening_rollback --yes || EXIT_CODE=1
      else
        hardening_rollback || EXIT_CODE=1
      fi
      ;;
    daily_summary)
      action_daily_summary
      ;;
    test_alert)
      action_test_alert
      ;;
    *)
      log_error "Unknown action: $ACTION"
      exit 3
      ;;
  esac

  exit "$EXIT_CODE"
}

main "$@"
