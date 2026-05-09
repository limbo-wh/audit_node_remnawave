#!/usr/bin/env bash
# lib/ports.sh — port drift detection + интерактивный sync + wizard для install.sh.
#
# Источники истины:
#   1. docker-compose.yml ноды — NODE_PORT.
#   2. ss -tlnp + docker top — реально слушающие порты xray.
#   3. ufw status — allow-list.
#   4. audit.conf — NODE_PORT, INBOUND_PORTS, EXTRA_PORTS_WHITELIST.
#   5. sshd_config — Port (для UFW whitelist'а).
#
# Главное правило: ports.sh ничего сам не правит автоматически (кроме
# ports_sync_interactive, и только после явного y от админа).

readonly REMNANODE_COMPOSE_PATH="${REMNANODE_COMPOSE:-/opt/remnanode/docker-compose.yml}"
readonly REMNANODE_NAME="${REMNANODE_CONTAINER:-remnanode}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# CSV-нормализация: убираем пустые, дедуп, sort numeric.
# Защитный ${1:-} — иначе под set -u падает unbound variable.
_csv_normalize() {
  printf '%s' "${1:-}" | tr ',' '\n' | awk 'NF' | sort -un | paste -sd, - || true
}

# Проверка содержит ли CSV строка значение (точное совпадение).
_csv_contains() {
  local csv="$1" needle="$2"
  printf ',%s,' "$csv" | grep -qF ",${needle},"
}

# CSV1 минус CSV2 (значения из 1, которых нет в 2).
_csv_diff() {
  local a="$1" b="$2" out="" v
  local IFS=','
  for v in $a; do
    [[ -z "$v" ]] && continue
    if ! _csv_contains "$b" "$v"; then
      out+="${v},"
    fi
  done
  unset IFS
  printf '%s' "${out%,}"
}

# ---------------------------------------------------------------------------
# Источники
# ---------------------------------------------------------------------------

# SSH-порт из sshd_config (default 22).
ports_sshd_port() {
  local p
  p="$(awk '/^[Pp]ort /{print $2; exit}' /etc/ssh/sshd_config 2>/dev/null)"
  printf '%s' "${p:-22}"
}

# NODE_PORT из /opt/remnanode/docker-compose.yml.
# Поддерживает форматы: NODE_PORT=2222, - "NODE_PORT=2222", NODE_PORT: 2222.
ports_compose_node_port() {
  [[ -f "$REMNANODE_COMPOSE_PATH" ]] || return 0
  grep -E 'NODE_PORT[=:]' "$REMNANODE_COMPOSE_PATH" 2>/dev/null \
    | head -1 | grep -oE '[0-9]+' | tail -1
}

# Реально слушающие TCP-порты всех процессов контейнера remnanode.
# Берём ВСЕ PID-ы контейнера (не только xray-named), потому что в образе
# remnawave/node главный процесс — node, который форкает xray как child.
# network_mode: host → процессы видны с хоста, ss их найдёт по PID.
ports_listening_xray() {
  command -v docker >/dev/null 2>&1 || return 0
  command -v ss >/dev/null 2>&1 || return 0
  local pids pid_re
  pids="$(timeout 3 docker top "$REMNANODE_NAME" -o pid 2>/dev/null \
            | awk 'NR>1 && $1 ~ /^[0-9]+$/ {print $1}' || true)"
  if [[ -z "$pids" ]]; then
    pids="$(docker inspect --format '{{.State.Pid}}' "$REMNANODE_NAME" 2>/dev/null || true)"
    [[ -z "$pids" || "$pids" == "0" ]] && return 0
  fi
  pid_re="$(printf '%s' "$pids" | tr '\n' '|' | sed 's/^|//;s/|$//' || true)"
  # -p даёт users:(("name",pid=N,fd=K)) в выводе.
  # Используем [^0-9] вместо \b — не зависит от awk dialect (mawk vs gawk).
  ss -tlnpH 2>/dev/null \
    | awk -v re="pid=(${pid_re})[^0-9]" '$0 ~ re {n=split($4,a,":"); print a[n]}' \
    | sort -un || true
}

# Все слушающие TCP-порты на хосте (для альтернативного просмотра).
ports_listening_host() {
  command -v ss >/dev/null 2>&1 || return 0
  ss -tlnH 2>/dev/null | awk '{n=split($4,a,":"); print a[n]}' \
    | grep -E '^[0-9]+$' | sort -un || true
}

# UFW allow-list (только integer порты; range/protocol-spec пропускаются).
ports_ufw_allow() {
  command -v ufw >/dev/null 2>&1 || return 0
  ufw status 2>/dev/null \
    | awk '/ALLOW/ {p=$1; sub(/\/.*/,"",p); if (p ~ /^[0-9]+$/) print p}' \
    | sort -un || true
}

# CSV из значения функции, печатающей построчно.
_to_csv() { paste -sd, - ; }

# Заявленный whitelist из конфига: NODE_PORT + INBOUND_PORTS + EXTRA_PORTS_WHITELIST.
ports_declared_csv() {
  local s=""
  [[ -n "${NODE_PORT:-}" ]] && s+="${NODE_PORT},"
  [[ -n "${INBOUND_PORTS:-}" ]] && s+="${INBOUND_PORTS},"
  [[ -n "${EXTRA_PORTS_WHITELIST:-}" ]] && s+="${EXTRA_PORTS_WHITELIST},"
  _csv_normalize "${s%,}"
}

# Полный whitelist (с SSH) — то, что должно быть в UFW.
ports_full_whitelist_csv() {
  local s
  s="$(ports_sshd_port),$(ports_declared_csv)"
  _csv_normalize "$s"
}

# ---------------------------------------------------------------------------
# Drift detection (зовётся из checks_run_all)
# ---------------------------------------------------------------------------

ports_drift_check() {
  local listening_csv compose_port ufw_csv conf_node conf_inbound declared_csv
  listening_csv="$(ports_listening_xray | _to_csv)"
  compose_port="$(ports_compose_node_port)"
  ufw_csv="$(ports_ufw_allow | _to_csv)"
  conf_node="${NODE_PORT:-}"
  conf_inbound="${INBOUND_PORTS:-}"
  declared_csv="$(ports_declared_csv)"

  # 1. NODE_PORT в docker-compose ≠ значению в audit.conf → CRIT.
  if [[ -n "$compose_port" && -n "$conf_node" && "$compose_port" != "$conf_node" ]]; then
    _emit CRIT ports_node_port_drift \
      "NODE_PORT изменился: ${conf_node} → ${compose_port}" \
"Источник: ${REMNANODE_COMPOSE_PATH}.
UFW не пропускает ${compose_port} → панель потеряет связь.
Починить:
  sudo ufw allow ${compose_port}/tcp comment 'remnanode'
  sudo sed -i 's/^NODE_PORT=.*/NODE_PORT=${compose_port}/' /etc/remnawave-audit/audit.conf"
  fi

  # 2. UFW не пропускает заявленный NODE_PORT → CRIT.
  if [[ -n "$conf_node" && -n "$ufw_csv" ]] && ! _csv_contains "$ufw_csv" "$conf_node"; then
    _emit CRIT ports_node_port_blocked \
      "UFW не пропускает NODE_PORT=${conf_node}" \
      "Панель не достукивается. sudo ufw allow ${conf_node}/tcp comment 'remnanode'"
  fi

  # 3. Слушает порт, которого нет ни в declared, ни в EXTRA → WARN.
  if [[ -n "$listening_csv" ]]; then
    local p
    local IFS=','
    for p in $listening_csv; do
      [[ -z "$p" ]] && continue
      if ! _csv_contains "$declared_csv" "$p"; then
        _emit WARN "ports_unknown_listening_${p}" \
          "Обнаружен новый порт: tcp/${p}" \
"Слушает xray, но не указан в audit.conf.
Похоже, добавили инбаунд через панель.
Разрешить:
  sudo ufw allow ${p}/tcp comment 'remnanode inbound'
  sudo audit.sh --sync-ports"
      fi
    done
    unset IFS
  fi

  # 4. Заявленный INBOUND не слушает никто → WARN.
  if [[ -n "$conf_inbound" && -n "$listening_csv" ]]; then
    local p
    local IFS=','
    for p in $conf_inbound; do
      [[ -z "$p" ]] && continue
      if ! _csv_contains "$listening_csv" "$p"; then
        _emit WARN "ports_inbound_silent_${p}" \
          "Заявленный инбаунд tcp/${p} не слушает" \
          "Возможно, убран из панели. Можно убрать из UFW и audit.conf"
      fi
    done
    unset IFS
  fi

  _emit OK ports_drift_summary \
    "listening=[${listening_csv:-?}] declared=[${declared_csv:-?}] ufw=[${ufw_csv:-?}]" ""
}

# ---------------------------------------------------------------------------
# --show-ports
# ---------------------------------------------------------------------------

ports_show_table() {
  local listening compose_port ufw conf_node conf_inbound ssh_port whitelist
  listening="$(ports_listening_xray | _to_csv)"
  compose_port="$(ports_compose_node_port)"
  ufw="$(ports_ufw_allow | _to_csv)"
  conf_node="${NODE_PORT:-}"
  conf_inbound="${INBOUND_PORTS:-}"
  ssh_port="$(ports_sshd_port)"
  whitelist="$(ports_full_whitelist_csv)"

  cat <<EOF
=== Ports inventory (${NODE_NAME:-node}) ===

SSH (sshd_config):     ${ssh_port}
NODE_PORT (compose):   ${compose_port:-?}
NODE_PORT (audit.conf):${conf_node:-?}
INBOUND_PORTS:         ${conf_inbound:-?}
EXTRA_WHITELIST:       ${EXTRA_PORTS_WHITELIST:-}

Реально слушает xray: ${listening:-?}
В UFW allow:          ${ufw:-?}
Полный whitelist:     ${whitelist}

=== Drift ===
EOF

  local res
  res="$(ports_drift_check)"
  if [[ -z "$res" ]]; then
    printf '  (нет результатов — docker/ufw недоступны?)\n'
    return 0
  fi
  local sev key msg
  while IFS='|' read -r sev key msg _; do
    [[ -z "$sev" ]] && continue
    case "$sev" in
      CRIT) printf '  🔴 [%s] %s\n' "$key" "$msg" ;;
      WARN) printf '  🟡 [%s] %s\n' "$key" "$msg" ;;
      OK)   printf '  ✓  %s\n' "$msg" ;;
    esac
  done <<<"$res"
}

# ---------------------------------------------------------------------------
# --sync-ports (interactive)
# ---------------------------------------------------------------------------

ports_sync_interactive() {
  is_root || { log_error "--sync-ports требует root"; return 1; }

  ports_show_table
  printf '\n'

  local listening declared diff_csv
  listening="$(ports_listening_xray | _to_csv)"
  declared="$(ports_declared_csv)"
  diff_csv="$(_csv_diff "$listening" "$declared")"

  if [[ -z "$diff_csv" ]]; then
    log_info "Drift не обнаружен — всё синхронизировано."
    return 0
  fi

  printf 'Слушает но не разрешено: %s\n' "$diff_csv"
  printf 'Применить (ufw allow + дописать в INBOUND_PORTS)? [y/N]: '
  local reply
  read -r reply
  if [[ "$reply" != "y" && "$reply" != "Y" ]]; then
    log_info "Отменено."
    return 0
  fi

  if ! command -v ufw >/dev/null 2>&1; then
    log_error "ufw не установлен — не могу применить."
    return 1
  fi

  local p
  local IFS=','
  for p in $diff_csv; do
    [[ -z "$p" ]] && continue
    log_info "ufw allow ${p}/tcp"
    ufw allow "${p}/tcp" comment 'remnanode inbound (sync-ports)' >/dev/null || \
      log_warn "ufw allow ${p} failed"
  done
  unset IFS

  # Дописываем в audit.conf новые порты в INBOUND_PORTS.
  # NB: _csv_normalize читает $1 (не stdin) — нельзя через pipe!
  local new_inbound
  new_inbound="$(_csv_normalize "${INBOUND_PORTS:-},${diff_csv}")"
  if [[ -f "$CONFIG_PATH" ]]; then
    if grep -q '^INBOUND_PORTS=' "$CONFIG_PATH"; then
      sed -i "s|^INBOUND_PORTS=.*|INBOUND_PORTS=${new_inbound}|" "$CONFIG_PATH"
    else
      printf 'INBOUND_PORTS=%s\n' "$new_inbound" >> "$CONFIG_PATH"
    fi
    log_info "audit.conf обновлён: INBOUND_PORTS=${new_inbound}"
  else
    log_warn "Конфиг ${CONFIG_PATH} не найден — пропуск записи INBOUND_PORTS"
  fi

  log_info "Синхронизация завершена."
}

# ---------------------------------------------------------------------------
# Port wizard (для install.sh)
# ---------------------------------------------------------------------------

# ports_wizard
# Интерактивно собирает NODE_PORT и INBOUND_PORTS. Экспортирует:
#   WIZARD_NODE_PORT, WIZARD_INBOUND_PORTS, WIZARD_FULL_WHITELIST
ports_wizard() {
  local ssh_port compose_port default_node
  ssh_port="$(ports_sshd_port)"
  compose_port="$(ports_compose_node_port)"
  default_node="${compose_port:-2222}"

  printf '\n[1/3] SSH-порт из sshd_config: %s — будет открыт в UFW.\n' "$ssh_port"

  printf '[2/3] NODE_PORT (связь с панелью): %s\n' "$default_node"
  printf '      Использовать его? [Y/n]: '
  local reply
  read -r reply
  if [[ "$reply" == "n" || "$reply" == "N" ]]; then
    printf '      Введите NODE_PORT: '
    read -r WIZARD_NODE_PORT
  else
    WIZARD_NODE_PORT="$default_node"
  fi
  if [[ ! "$WIZARD_NODE_PORT" =~ ^[0-9]+$ ]] || (( WIZARD_NODE_PORT < 1 || WIZARD_NODE_PORT > 65535 )); then
    log_error "NODE_PORT некорректен: ${WIZARD_NODE_PORT}"
    return 1
  fi

  printf '[3/3] Стандартные порты инбаундов: 443, 8388\n'
  printf '      [s] Использовать стандартные\n'
  printf '      [c] Ввести свои (если меняли в панели)\n'
  printf '      [a] Добавить дополнительные к стандартным\n'
  printf '      Выбор [s/c/a, default s]: '
  local choice extra
  read -r choice
  case "${choice:-s}" in
    c|C)
      printf '      Введите CSV портов инбаундов: '
      read -r WIZARD_INBOUND_PORTS
      ;;
    a|A)
      printf '      Дополнительные порты (CSV): '
      read -r extra
      WIZARD_INBOUND_PORTS="$(_csv_normalize "443,8388,${extra}")"
      ;;
    *)
      WIZARD_INBOUND_PORTS="443,8388"
      ;;
  esac
  WIZARD_INBOUND_PORTS="$(_csv_normalize "$WIZARD_INBOUND_PORTS")"

  WIZARD_FULL_WHITELIST="$(_csv_normalize "${ssh_port},${WIZARD_NODE_PORT},${WIZARD_INBOUND_PORTS}")"

  printf '\nИтоговый allow-list UFW: %s\n' "$WIZARD_FULL_WHITELIST"
  printf 'Сохранить и применить? [Y/n]: '
  read -r reply
  [[ "$reply" == "n" || "$reply" == "N" ]] && return 1
  return 0
}
