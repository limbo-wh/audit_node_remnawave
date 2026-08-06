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
  # Фильтруем localhost-only сокеты (127.x / [::1]) — они недоступны снаружи
  # и не должны попадать в UFW whitelist (напр. внутренний gRPC/stats порт xray).
  ss -tlnpH 2>/dev/null \
    | awk -v re="pid=(${pid_re})[^0-9]" '
        $0 ~ re {
          n = split($4, a, ":");
          port = a[n];
          addr = substr($4, 1, length($4) - length(port) - 1);
          if (addr ~ /^127\./ || addr == "[::1]" || addr == "::1") next;
          print port
        }' \
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

# Полный разбор allow-правил UFW со ЗНАЧЕНИЕМ source.
# Формат вывода (по строке на правило):  port|proto|from|comment
#   from == "Anywhere" — правило открыто миру
#   from == "155.212.132.159" / "10.0.0.0/8" — правило ограничено по source
#
# Зачем: ports_ufw_allow() отдаёт только номера портов, и по нему невозможно
# отличить `allow 2222/tcp` (открыт всем) от
# `allow from <IP панели> to any port 2222` (ограничен). Без этого различия
# любая пересборка UFW молча снимает ограничение по IP.
#
# v6-дубли схлопываются: `22/tcp (v6)` и `22/tcp` — одно логическое правило.
ports_ufw_rules() {
  command -v ufw >/dev/null 2>&1 || return 0
  ufw status 2>/dev/null | awk '
    {
      line = $0
      comment = ""
      h = index(line, "#")
      if (h > 0) {
        comment = substr(line, h + 1)
        line = substr(line, 1, h - 1)
        gsub(/^[ \t]+|[ \t]+$/, "", comment)
      }
      gsub(/\(v6\)/, "", line)

      n = split(line, f, " ")
      ai = 0
      for (k = 1; k <= n; k++) if (f[k] == "ALLOW") { ai = k; break }
      if (ai == 0) next

      to = f[1]
      port = to; proto = "any"
      s = index(to, "/")
      if (s > 0) { port = substr(to, 1, s - 1); proto = substr(to, s + 1) }
      if (port !~ /^[0-9]+$/) next

      fi = ai + 1
      if (f[fi] == "IN" || f[fi] == "OUT") fi++
      from = (fi <= n && f[fi] != "") ? f[fi] : "Anywhere"

      print port "|" proto "|" from "|" comment
    }' | sort -u || true
}

# Есть ли в UFW хоть одно allow-правило на порт (с любым source)?
# Порт «покрыт» — трогать его не нужно, даже если source отличается от нашего.
ports_ufw_has_port() {
  local port="$1"
  [[ -n "$port" ]] || return 1
  ports_ufw_rules | awk -F'|' -v p="$port" '$1 == p {found=1} END {exit !found}'
}

# Source-IP для порта: первый не-Anywhere source среди правил этого порта.
# Пусто — если правил нет или все открыты миру.
ports_ufw_source_for() {
  local port="$1"
  [[ -n "$port" ]] || return 0
  ports_ufw_rules \
    | awk -F'|' -v p="$port" '$1 == p && $3 != "Anywhere" && $3 != "" {print $3; exit}'
}

# Порты, открытые в UFW, но отсутствующие в переданном whitelist (CSV).
ports_ufw_extras_csv() {
  local whitelist="$1" out="" p
  local existing
  existing="$(ports_ufw_allow | _to_csv)"
  [[ -n "$existing" ]] || return 0
  local IFS=','
  for p in $existing; do
    [[ -z "$p" ]] && continue
    if ! _csv_contains "$whitelist" "$p"; then
      out+="${p},"
    fi
  done
  unset IFS
  printf '%s' "${out%,}"
}

# ignoreip из ЧУЖИХ fail2ban-конфигов (jail.local + jail.d/*, кроме нашего).
# Нужно, чтобы установка переняла уже внесённые админом доверенные IP,
# а не сузила их до дефолта.
ports_fail2ban_ignoreip() {
  local f out=""
  local f2b_dir="${FAIL2BAN_DIR:-/etc/fail2ban}"
  for f in "${f2b_dir}/jail.local" "${f2b_dir}"/jail.d/*.conf "${f2b_dir}"/jail.d/*.local; do
    [[ -f "$f" ]] || continue
    [[ "$f" == "${f2b_dir}/jail.d/remnawave-audit.local" ]] && continue
    out+="$(awk -F'=' '/^[[:space:]]*ignoreip[[:space:]]*=/ {print $2}' "$f" 2>/dev/null || true) "
  done
  # Отбрасываем loopback — он и так всегда в нашем ignoreip.
  printf '%s' "$out" | tr ' ' '\n' | awk 'NF' \
    | grep -vE '^(127\.|::1$|127\.0\.0\.1/8$)' | sort -u | paste -sd, - || true
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

  local changed=0

  # --- Блок 1: новые порты (xray слушает, но не в whitelist) ---
  if [[ -n "$diff_csv" ]]; then
    printf 'Слушает но не разрешено: %s\n' "$diff_csv"
    printf 'Применить (ufw allow + добавить в INBOUND_PORTS)? [y/N]: '
    local reply
    read -r reply
    if [[ "$reply" == "y" || "$reply" == "Y" ]]; then
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
      local new_inbound
      new_inbound="$(_csv_normalize "${INBOUND_PORTS:-},${diff_csv}")"
      if [[ -f "$CONFIG_PATH" ]]; then
        if grep -q '^INBOUND_PORTS=' "$CONFIG_PATH"; then
          sed -i "s|^INBOUND_PORTS=.*|INBOUND_PORTS=${new_inbound}|" "$CONFIG_PATH"
        else
          printf 'INBOUND_PORTS=%s\n' "$new_inbound" >> "$CONFIG_PATH"
        fi
        INBOUND_PORTS="$new_inbound"
        log_info "audit.conf обновлён: INBOUND_PORTS=${new_inbound}"
      else
        log_warn "Конфиг ${CONFIG_PATH} не найден — пропуск записи INBOUND_PORTS"
      fi
      changed=1
    fi
  fi

  # --- Блок 2: пропавшие порты (в INBOUND_PORTS, но xray больше не слушает) ---
  # Пропускаем если xray не запущен совсем (listening пустой) — иначе предложим
  # удалить всё, что некорректно.
  if [[ -n "$listening" && -n "${INBOUND_PORTS:-}" ]]; then
    local gone_csv
    gone_csv="$(_csv_diff "${INBOUND_PORTS:-}" "$listening")"
    if [[ -n "$gone_csv" ]]; then
      printf '\nЗаявлены в INBOUND_PORTS, но xray не слушает: %s\n' "$gone_csv"
      printf 'Убрать из audit.conf и UFW? [y/N]: '
      local reply2
      read -r reply2
      if [[ "$reply2" == "y" || "$reply2" == "Y" ]]; then
        local p2
        local IFS=','
        for p2 in $gone_csv; do
          [[ -z "$p2" ]] && continue
          log_info "ufw delete allow ${p2}/tcp"
          ufw delete allow "${p2}/tcp" >/dev/null 2>&1 || true
          ufw delete allow "${p2}"     >/dev/null 2>&1 || true
        done
        unset IFS
        local cleaned_inbound
        cleaned_inbound="$(_csv_diff "${INBOUND_PORTS:-}" "$gone_csv")"
        if [[ -f "$CONFIG_PATH" ]]; then
          sed -i "s|^INBOUND_PORTS=.*|INBOUND_PORTS=${cleaned_inbound}|" "$CONFIG_PATH"
          INBOUND_PORTS="$cleaned_inbound"
          log_info "audit.conf обновлён: INBOUND_PORTS=${cleaned_inbound}"
        fi
        changed=1
      fi
    fi
  fi

  if (( changed == 0 )) && [[ -z "$diff_csv" ]]; then
    log_info "Drift не обнаружен — всё синхронизировано."
  elif (( changed == 0 )); then
    log_info "Изменения не применены."
  else
    log_info "Синхронизация завершена."
  fi
}

# ---------------------------------------------------------------------------
# Port wizard (для install.sh)
# ---------------------------------------------------------------------------

# IP или CIDR (v4/v6, грубая проверка — достаточно чтобы отсечь опечатки).
_is_ip_or_cidr() {
  [[ "$1" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$ ]] && return 0
  [[ "$1" =~ ^[0-9a-fA-F:]+(/[0-9]{1,3})?$ && "$1" == *:* ]] && return 0
  return 1
}

# Каждый элемент CSV — валидный IP/CIDR.
_csv_all_ips() {
  local v
  local IFS=','
  for v in $1; do
    [[ -z "$v" ]] && continue
    _is_ip_or_cidr "$v" || return 1
  done
  unset IFS
  return 0
}

# ports_wizard
# Интерактивно собирает параметры портов и — что важнее — ПЕРЕНИМАЕТ уже
# настроенную на сервере безопасность: существующие правила UFW (включая
# ограничения по source-IP) и ignoreip из чужих fail2ban jail'ов.
# Экспортирует:
#   WIZARD_NODE_PORT, WIZARD_INBOUND_PORTS, WIZARD_EXTRA_PORTS,
#   WIZARD_NODE_PORT_ALLOW_FROM, WIZARD_SSH_ADMIN_IPS,
#   WIZARD_UFW_MODE, WIZARD_FULL_WHITELIST
ports_wizard() {
  local ssh_port compose_port default_node
  ssh_port="$(ports_sshd_port)"
  compose_port="$(ports_compose_node_port)"
  default_node="${compose_port:-2222}"

  WIZARD_EXTRA_PORTS=""
  WIZARD_NODE_PORT_ALLOW_FROM=""
  WIZARD_SSH_ADMIN_IPS=""
  WIZARD_UFW_MODE="preserve"

  local ufw_active=0
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | head -1 | grep -q 'Status: active'; then
    ufw_active=1
  fi

  printf '\n[1/5] SSH-порт из sshd_config: %s — будет открыт в UFW.\n' "$ssh_port"

  printf '[2/5] NODE_PORT (связь с панелью): %s\n' "$default_node"
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

  # Ограничение порта панели по source-IP. Если админ уже настроил такое
  # правило руками — подставляем его значение, чтобы установка не ослабила
  # доступ, расширив правило до Anywhere.
  local detected_src
  detected_src="$(ports_ufw_source_for "$WIZARD_NODE_PORT")"
  if [[ -n "$detected_src" ]]; then
    printf '      В UFW порт %s уже ограничен source: %s\n' "$WIZARD_NODE_PORT" "$detected_src"
    printf '      Сохранить это ограничение? [Y/n]: '
    read -r reply
    if [[ "$reply" == "n" || "$reply" == "N" ]]; then
      WIZARD_NODE_PORT_ALLOW_FROM=""
    else
      WIZARD_NODE_PORT_ALLOW_FROM="$detected_src"
    fi
  else
    printf '      IP панели для ограничения доступа к порту %s (Enter — открыть всем): ' "$WIZARD_NODE_PORT"
    read -r WIZARD_NODE_PORT_ALLOW_FROM
    if [[ -n "$WIZARD_NODE_PORT_ALLOW_FROM" ]] && ! _is_ip_or_cidr "$WIZARD_NODE_PORT_ALLOW_FROM"; then
      log_error "Не похоже на IP/CIDR: ${WIZARD_NODE_PORT_ALLOW_FROM}"
      return 1
    fi
  fi

  # Пытаемся определить реальные порты xray, исключая NODE_PORT.
  local detected_inbound default_inbound
  detected_inbound="$(ports_listening_xray 2>/dev/null \
    | grep -v "^${WIZARD_NODE_PORT}$" | _to_csv || true)"
  if [[ -n "$detected_inbound" ]]; then
    default_inbound="$detected_inbound"
    printf '[3/5] Обнаруженные порты инбаундов xray: %s\n' "$default_inbound"
  else
    default_inbound="443"
    printf '[3/5] Порты инбаундов xray (не удалось определить автоматически): %s\n' "$default_inbound"
  fi
  printf '      [s] Использовать обнаруженные (%s)\n' "$default_inbound"
  printf '      [c] Ввести свои\n'
  printf '      [a] Добавить дополнительные к обнаруженным\n'
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
      WIZARD_INBOUND_PORTS="$(_csv_normalize "${default_inbound},${extra}")"
      ;;
    *)
      WIZARD_INBOUND_PORTS="$default_inbound"
      ;;
  esac
  WIZARD_INBOUND_PORTS="$(_csv_normalize "$WIZARD_INBOUND_PORTS")"

  # --- Уже открытые в UFW порты, не попавшие в наш whitelist ---
  # Раньше они всплывали только на этапе hardening'а — как ошибка, обрывающая
  # установку. Правильное место разобраться с ними — здесь, до записи конфига.
  # Порты вроде 80 (nginx front) или 8444 (XHTTP) не видны через docker top,
  # поэтому автоопределение инбаундов их принципиально не находит.
  local base_wl known_extras
  base_wl="$(_csv_normalize "${ssh_port},${WIZARD_NODE_PORT},${WIZARD_INBOUND_PORTS}")"
  known_extras="$(ports_ufw_extras_csv "$base_wl")"

  printf '[4/5] Дополнительные порты (не инбаунды xray)\n'
  if [[ -n "$known_extras" ]]; then
    printf '      В UFW уже открыты и не учтены выше: %s\n' "$known_extras"
    printf '      Обычно это nginx/фронт (80), XHTTP (8444) и подобное.\n'
    printf '      Записать их в EXTRA_PORTS_WHITELIST? [Y/n]: '
    read -r reply
    if [[ "$reply" == "n" || "$reply" == "N" ]]; then
      printf '      Свой список (CSV, Enter — пусто): '
      read -r WIZARD_EXTRA_PORTS
    else
      WIZARD_EXTRA_PORTS="$known_extras"
    fi
  else
    printf '      Не обнаружено. Доп. порты (CSV, Enter — пропустить): '
    read -r WIZARD_EXTRA_PORTS
  fi
  WIZARD_EXTRA_PORTS="$(_csv_normalize "$WIZARD_EXTRA_PORTS")"

  # --- Режим применения UFW ---
  printf '[5/5] Режим UFW\n'
  if (( ufw_active == 1 )); then
    printf '      UFW уже активен. Как применять правила?\n'
    printf '      [p] preserve — только добавить недостающее, ничего не удалять (рекомендуется)\n'
    printf '      [r] reset    — пересобрать список правил с нуля\n'
    printf '      Выбор [p/r, default p]: '
    read -r choice
    case "${choice:-p}" in
      r|R) WIZARD_UFW_MODE="reset" ;;
      *)   WIZARD_UFW_MODE="preserve" ;;
    esac
  else
    printf '      UFW неактивен — правила будут созданы с нуля.\n'
    WIZARD_UFW_MODE="preserve"
  fi

  # --- Доверенные IP для fail2ban ---
  local detected_ignore
  detected_ignore="$(ports_fail2ban_ignoreip)"
  if [[ -n "$detected_ignore" ]]; then
    printf '\n      В fail2ban уже доверены IP: %s\n' "$detected_ignore"
    printf '      Перенести в SSH_ADMIN_IPS (не считать их брутфорсом)? [Y/n]: '
    read -r reply
    if [[ "$reply" != "n" && "$reply" != "N" ]]; then
      WIZARD_SSH_ADMIN_IPS="$detected_ignore"
    fi
  else
    printf '\n      Админские IP через запятую (Enter — пропустить): '
    read -r WIZARD_SSH_ADMIN_IPS
    if [[ -n "$WIZARD_SSH_ADMIN_IPS" ]] && ! _csv_all_ips "$WIZARD_SSH_ADMIN_IPS"; then
      log_error "SSH_ADMIN_IPS: ожидается CSV из IP/CIDR, получено: ${WIZARD_SSH_ADMIN_IPS}"
      return 1
    fi
  fi

  WIZARD_FULL_WHITELIST="$(_csv_normalize \
    "${ssh_port},${WIZARD_NODE_PORT},${WIZARD_INBOUND_PORTS},${WIZARD_EXTRA_PORTS}")"

  printf '\n--- Итог ---\n'
  printf 'Allow-list UFW:      %s\n' "$WIZARD_FULL_WHITELIST"
  printf 'Режим UFW:           %s\n' "$WIZARD_UFW_MODE"
  if [[ -n "$WIZARD_NODE_PORT_ALLOW_FROM" ]]; then
    printf 'Порт панели %-8s только с %s\n' "$WIZARD_NODE_PORT" "$WIZARD_NODE_PORT_ALLOW_FROM"
  else
    printf 'Порт панели %-8s открыт всем\n' "$WIZARD_NODE_PORT"
  fi
  printf 'Доверенные IP:       %s\n' "${WIZARD_SSH_ADMIN_IPS:-—}"
  if [[ "$WIZARD_UFW_MODE" == "preserve" ]] && (( ufw_active == 1 )); then
    printf '\nСуществующие правила UFW не будут удалены.\n'
  fi
  printf 'Сохранить и применить? [Y/n]: '
  read -r reply
  [[ "$reply" == "n" || "$reply" == "N" ]] && return 1
  return 0
}
