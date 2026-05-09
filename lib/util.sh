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

on_error() {
  local exit_code="$1"
  local line_no="$2"
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
