#!/usr/bin/env bash
# lib/util.sh — общие helpers: логирование, traps, проверки.
# Sourced из audit.sh и install.sh. Не запускается напрямую.

log_info()  { _log "INFO"  "$*"; }
log_warn()  { _log "WARN"  "$*"; }
log_error() { _log "ERROR" "$*"; }
log_debug() { [[ "${DEBUG:-0}" == "1" ]] && _log "DEBUG" "$*" || true; }

_log() {
  local level="$1"; shift
  local msg="$*"
  msg="$(secrets_mask "$msg")"
  printf '%(%Y-%m-%dT%H:%M:%S%z)T [%s] %s\n' -1 "$level" "$msg" >&2
}

# Контролируемый отказ: сработал guard, а не баг. Ставит флаг, чтобы trap ERR
# не выводил «Unexpected error at line N» — иначе осознанный abort выглядит
# как падение скрипта и админ ищет ошибку там, где её нет.
# Использование:  some_check || { abort_expected "причина"; return 1; }
abort_expected() {
  AUDIT_EXPECTED_ABORT=1
  [[ -n "$*" ]] && log_error "$*"
  return 1
}

on_error() {
  local exit_code="$1"
  local line_no="$2"
  if [[ "${AUDIT_EXPECTED_ABORT:-0}" == "1" ]]; then
    log_error "Прервано осознанно (см. сообщение выше). Изменения не применены."
    return 0
  fi
  log_error "Unexpected error at line ${line_no} (exit ${exit_code})"
}

on_exit() {
  # flock освобождается автоматически при закрытии fd 9 / выходе процесса.
  :
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    log_error "Required command not found: $1${2:+ ($2)}"
    exit 3
  fi
}

is_root() { [[ "$(id -u)" -eq 0 ]]; }
