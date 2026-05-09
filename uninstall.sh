#!/usr/bin/env bash
# uninstall.sh — удаление remnawave-node-audit с ноды.
#
# По умолчанию: остановка и удаление systemd unit'ов + logrotate.
# Флаг --purge: ДОПОЛНИТЕЛЬНО удалить /etc/remnawave-audit/, /var/lib/remnawave-audit/,
# /var/log/remnawave-audit/ — то есть все секреты, состояние, очередь, логи.
#
# Hardening (UFW/fail2ban/auto-upgrades) НЕ откатывается этим скриптом —
# для отката используй: audit.sh --rollback.

set -Eeuo pipefail
IFS=$'\n\t'

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly LIB_DIR="${SCRIPT_DIR}/lib"
readonly CONFIG_DIR="/etc/remnawave-audit"
readonly STATE_DIR="/var/lib/remnawave-audit"
readonly LOG_DIR="/var/log/remnawave-audit"
readonly LOGROTATE_FILE="/etc/logrotate.d/remnawave-audit"
readonly SYSTEMD_DIR="/etc/systemd/system"

# shellcheck source=lib/secrets.sh
. "${LIB_DIR}/secrets.sh"
# shellcheck source=lib/util.sh
. "${LIB_DIR}/util.sh"

OPT_PURGE=0
OPT_YES=0

usage() {
  cat <<'USAGE'
uninstall.sh — удаление remnawave-node-audit.

Использование:
  sudo ./uninstall.sh [--purge] [--yes]

Опции:
  --purge   удалить также конфиг (/etc/remnawave-audit/), состояние и логи
  --yes     не запрашивать подтверждение

Hardening (UFW/fail2ban/auto-upgrades) НЕ откатывается. Используй:
  sudo /opt/remnawave-audit/audit.sh --rollback
USAGE
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --purge) OPT_PURGE=1 ;;
      --yes)   OPT_YES=1 ;;
      -h|--help) usage; exit 0 ;;
      *) log_error "Неизвестный аргумент: $1"; usage; exit 1 ;;
    esac
    shift
  done
}

main() {
  parse_args "$@"
  is_root || { log_error "Запусти через sudo"; exit 1; }

  printf '=== uninstall remnawave-node-audit ===\n'
  printf 'Будет: остановка systemd unit'\''ов, удаление /etc/systemd/system/remnawave-audit*, %s\n' "$LOGROTATE_FILE"
  if (( OPT_PURGE == 1 )); then
    printf 'PURGE: + %s, %s, %s\n' "$CONFIG_DIR" "$STATE_DIR" "$LOG_DIR"
  else
    printf 'Конфиг и состояние оставлены (используй --purge для полного удаления)\n'
  fi
  printf 'Hardening НЕ откатывается. Для отката: %s/audit.sh --rollback\n\n' "$SCRIPT_DIR"

  if (( OPT_YES == 0 )); then
    printf 'Продолжить? [y/N]: '
    local reply; read -r reply
    [[ "$reply" != "y" && "$reply" != "Y" ]] && { log_info "Отменено"; exit 0; }
  fi

  for unit in remnawave-audit.timer remnawave-audit-daily.timer \
              remnawave-audit.service remnawave-audit-daily.service; do
    systemctl disable --now "$unit" >/dev/null 2>&1 || true
    rm -f "${SYSTEMD_DIR}/${unit}"
  done
  systemctl daemon-reload
  log_info "systemd unit'ы остановлены и удалены"

  if [[ -f "$LOGROTATE_FILE" ]]; then
    rm -f "$LOGROTATE_FILE"
    log_info "${LOGROTATE_FILE} удалён"
  fi

  if [[ -L /usr/local/bin/remnawave-audit ]]; then
    rm -f /usr/local/bin/remnawave-audit
    log_info "/usr/local/bin/remnawave-audit (симлинк) удалён"
  fi

  if (( OPT_PURGE == 1 )); then
    rm -rf "$CONFIG_DIR" "$STATE_DIR" "$LOG_DIR"
    log_info "Конфиг, состояние и логи удалены (purge)"
  fi

  printf '\n=== Готово ===\n'
}

main "$@"
