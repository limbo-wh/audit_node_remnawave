#!/usr/bin/env bash
# lib/state.sh — атомарное key/value хранилище в /var/lib/remnawave-audit/state.json.
# Sourced из audit.sh. Зависит от jq (проверяется в preflight).
#
# При DRY_RUN=1 / STATE_READONLY=1 запись отключена — функции _set возвращают 0
# без побочных эффектов, чтобы --dry-run не менял состояние.

readonly STATE_FILE="${STATE_DIR:-/var/lib/remnawave-audit}/state.json"

state_init() {
  mkdir -p "$(dirname "$STATE_FILE")"
  if [[ ! -f "$STATE_FILE" ]]; then
    printf '{}\n' > "$STATE_FILE"
    chmod 600 "$STATE_FILE"
  fi
}

# state_get <key> [default]
# Печатает значение ключа (строка/число/JSON-объект) или default, если ключа нет.
state_get() {
  local key="$1" default="${2:-}"
  if [[ ! -f "$STATE_FILE" ]]; then
    printf '%s' "$default"
    return 0
  fi
  jq -r --arg k "$key" --arg d "$default" '
    if has($k) then (.[$k] | if type == "string" then . else tostring end) else $d end
  ' "$STATE_FILE" 2>/dev/null || printf '%s' "$default"
}

# state_set <key> <value>
# Атомарно обновляет ключ. value сохраняется как строка.
state_set() {
  [[ "${DRY_RUN:-0}" == "1" || "${STATE_READONLY:-0}" == "1" ]] && return 0
  local key="$1" value="$2"
  state_init
  local tmp
  tmp="$(mktemp "${STATE_FILE}.XXXXXX")"
  if jq --arg k "$key" --arg v "$value" '. + {($k): $v}' "$STATE_FILE" > "$tmp"; then
    mv "$tmp" "$STATE_FILE"
    chmod 600 "$STATE_FILE"
  else
    rm -f "$tmp"
    log_warn "state_set failed for key=$key"
    return 1
  fi
}

# state_get_int <key> [default=0]
state_get_int() {
  local v
  v="$(state_get "$1" "${2:-0}")"
  [[ "$v" =~ ^-?[0-9]+$ ]] || v="${2:-0}"
  printf '%s' "$v"
}

# state_inc <key>
# Увеличивает счётчик на 1, возвращает новое значение.
state_inc() {
  local key="$1" cur
  cur="$(state_get_int "$key" 0)"
  cur=$((cur + 1))
  state_set "$key" "$cur"
  printf '%s' "$cur"
}

# state_get_array <key>
# Печатает CSV-список (хранится как строка через запятую). Пустая строка если нет.
state_get_array() {
  state_get "$1" ""
}

# state_set_array <key> <csv>
state_set_array() {
  state_set "$1" "$2"
}

# state_unset <key>
state_unset() {
  [[ "${DRY_RUN:-0}" == "1" || "${STATE_READONLY:-0}" == "1" ]] && return 0
  [[ -f "$STATE_FILE" ]] || return 0
  local key="$1" tmp
  tmp="$(mktemp "${STATE_FILE}.XXXXXX")"
  if jq --arg k "$key" 'del(.[$k])' "$STATE_FILE" > "$tmp"; then
    mv "$tmp" "$STATE_FILE"
    chmod 600 "$STATE_FILE"
  else
    rm -f "$tmp"
    return 1
  fi
}
