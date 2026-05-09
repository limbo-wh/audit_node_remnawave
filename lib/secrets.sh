#!/usr/bin/env bash
# lib/secrets.sh — маскирование секретов в любом выводе скрипта.
#
# Регистрирует строки, которые при логировании заменяются на '***'.
# Дополнительно ловит общеизвестные паттерны (BOT_TOKEN, длинные base64 SECRET_KEY/cert).
#
# ВАЖНО: source ДО первого log-вызова, иначе секреты могут утечь в journal/stderr.

_SECRETS_REGISTERED=()

# secrets_register <value> — добавить значение в список маскируемых.
# Безопасно вызывать многократно с одинаковым значением.
secrets_register() {
  local v="${1:-}"
  [[ -z "$v" ]] && return 0
  _SECRETS_REGISTERED+=("$v")
}

# secrets_mask <text> — вернуть текст с заменой секретов на '***'.
# 1) Маскируются известные регулярки (BOT_TOKEN, длинные base64-блобы).
# 2) Маскируются явно зарегистрированные строки (literal-замена через ${//}).
secrets_mask() {
  local text="${1:-}"
  local s

  # 1) Известные паттерны.
  # BOT_TOKEN: <digits>:<>=30 base64-ish>
  text="$(printf '%s' "$text" | sed -E 's/[0-9]+:[A-Za-z0-9_-]{30,}/***/g')"
  # Длинные base64-блобы (вероятно SECRET_KEY ноды или сертификат).
  text="$(printf '%s' "$text" | sed -E 's#[A-Za-z0-9+/=]{100,}#***#g')"

  # 2) Явно зарегистрированные значения (literal substitution, не regex).
  if (( ${#_SECRETS_REGISTERED[@]} > 0 )); then
    for s in "${_SECRETS_REGISTERED[@]}"; do
      [[ -z "$s" ]] && continue
      text="${text//"$s"/***}"
    done
  fi

  printf '%s' "$text"
}
