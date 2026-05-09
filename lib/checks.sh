#!/usr/bin/env bash
# lib/checks.sh — все проверки состояния ноды Remnawave.
#
# Соглашение: каждая check_* функция печатает на stdout 0+ строк формата
#   SEV|key|message|details
# где SEV ∈ {OK, INFO, WARN, CRIT}.
# 'OK' строки используются только для --diagnose (в Telegram не уходят).
#
# Зависимости: docker, jq, ss, openssl, curl, ping, awk, timedatectl.
# State (предыдущие значения) — через lib/state.sh.

readonly REMNANODE_CONTAINER="remnanode"
readonly REMNANODE_COMPOSE="/opt/remnanode/docker-compose.yml"
readonly REMNANODE_IMAGE="remnawave/node:latest"

# Кэш docker inspect для одного прогона (заполняется при первом обращении)
_DOCKER_INSPECT_JSON=""
_DOCKER_INSPECT_OK=0

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# _emit <sev> <key> <message> [details]
# details может быть многострочным — внутренние \n кодируем как \x01,
# чтобы построчный парсер `IFS='|' read` не разорвал запись.
# Декодирование обратно — в audit.sh::run_diagnose и lib/notify.sh::_notify_emit.
_emit() {
  local sev="$1" key="$2" msg="$3" details="${4:-}"
  details="${details//$'\n'/$'\x01'}"
  printf '%s|%s|%s|%s\n' "$sev" "$key" "$msg" "$details"
}

# _docker_inspect — кэшированный docker inspect remnanode.
# Возвращает 0 если контейнер найден, 1 если нет.
_docker_inspect() {
  if (( _DOCKER_INSPECT_OK == 0 )) && [[ -z "$_DOCKER_INSPECT_JSON" ]]; then
    if _DOCKER_INSPECT_JSON="$(timeout 5 docker inspect "$REMNANODE_CONTAINER" 2>/dev/null)"; then
      _DOCKER_INSPECT_OK=1
    else
      _DOCKER_INSPECT_OK=2  # marker: probed and failed
      return 1
    fi
  fi
  (( _DOCKER_INSPECT_OK == 1 )) && printf '%s' "$_DOCKER_INSPECT_JSON"
}

# _jq_inspect <jq filter> — извлечь поле из docker inspect.
_jq_inspect() {
  _docker_inspect | jq -r ".[0]$1" 2>/dev/null
}

# _ports_whitelist_csv — единый whitelist (делегируется к lib/ports.sh).
# Fallback на inline-логику если ports.sh ещё не sourced.
_ports_whitelist_csv() {
  if declare -F ports_full_whitelist_csv >/dev/null; then
    ports_full_whitelist_csv
    return
  fi
  local ssh_port
  ssh_port="$(awk '/^[Pp]ort /{print $2; exit}' /etc/ssh/sshd_config 2>/dev/null)"
  ssh_port="${ssh_port:-22}"
  local all="${ssh_port},${NODE_PORT:-2222}"
  [[ -n "${INBOUND_PORTS:-}" ]] && all+=",${INBOUND_PORTS}"
  [[ -n "${EXTRA_PORTS_WHITELIST:-}" ]] && all+=",${EXTRA_PORTS_WHITELIST}"
  printf '%s' "$all" | tr ',' '\n' | awk 'NF' | sort -un | paste -sd, -
}

# _to_unix <iso-8601> — RFC3339 → unix epoch.
_to_unix() {
  date -d "$1" +%s 2>/dev/null || printf '0'
}

# ---------------------------------------------------------------------------
# 3.1 Container
# ---------------------------------------------------------------------------

check_container() {
  if ! _docker_inspect >/dev/null; then
    _emit CRIT container_missing "Контейнер ${REMNANODE_CONTAINER} отсутствует" \
      "docker inspect ${REMNANODE_CONTAINER} → not found"
    return
  fi

  local status restart_count health started_at image image_id
  status="$(_jq_inspect '.State.Status')"
  restart_count="$(_jq_inspect '.RestartCount')"
  health="$(_jq_inspect '.State.Health.Status // "none"')"
  started_at="$(_jq_inspect '.State.StartedAt')"
  image="$(_jq_inspect '.Config.Image')"
  image_id="$(_jq_inspect '.Image')"

  if [[ "$status" != "running" ]]; then
    local exit_code
    exit_code="$(_jq_inspect '.State.ExitCode')"
    _emit CRIT container_status "Контейнер ${REMNANODE_CONTAINER} не running: ${status}" \
      "ExitCode=${exit_code} RestartCount=${restart_count} Image=${image}"
    return
  fi

  local prev_count
  prev_count="$(state_get_int "container_restart_count" "$restart_count")"
  state_set "container_restart_count" "$restart_count"
  if (( restart_count > prev_count )); then
    _emit WARN container_restarted "Контейнер перезапустился: ${prev_count} → ${restart_count}" \
      "Started: ${started_at}"
  fi

  if [[ "$health" == "unhealthy" ]]; then
    _emit CRIT container_unhealthy "Healthcheck контейнера: unhealthy" "Image=${image}"
  fi

  # CPU / RAM из docker stats
  local stats cpu mem
  if stats="$(timeout 5 docker stats --no-stream --format '{{.CPUPerc}}|{{.MemPerc}}|{{.MemUsage}}' "$REMNANODE_CONTAINER" 2>/dev/null)"; then
    IFS='|' read -r cpu mem _ <<<"$stats"
    cpu="${cpu%\%}"
    mem="${mem%\%}"
    if [[ -n "$cpu" ]] && awk "BEGIN{exit !($cpu+0 > ${THRESHOLD_CPU:-80})}"; then
      _emit WARN container_cpu_high "CPU контейнера: ${cpu}% (порог ${THRESHOLD_CPU:-80}%)" ""
    fi
    if [[ -n "$mem" ]] && awk "BEGIN{exit !($mem+0 > ${THRESHOLD_RAM:-85})}"; then
      _emit WARN container_ram_high "RAM контейнера: ${mem}% (порог ${THRESHOLD_RAM:-85}%)" ""
    fi
    _emit OK container_stats "CPU=${cpu}% RAM=${mem}%" ""
  fi

  # Image digest cache (для алерта при смене образа админом)
  local prev_image_id
  prev_image_id="$(state_get "container_image_id" "$image_id")"
  state_set "container_image_id" "$image_id"
  if [[ -n "$prev_image_id" && "$prev_image_id" != "$image_id" ]]; then
    _emit INFO container_image_changed "Образ контейнера обновлён" \
      "Был: ${prev_image_id:0:19}… Стал: ${image_id:0:19}…"
  fi
}

# ---------------------------------------------------------------------------
# 3.2 Network
# ---------------------------------------------------------------------------

check_network_listen() {
  local port="${NODE_PORT:-2222}"
  if ! ss -tln 2>/dev/null | awk -v p=":${port}$" '$4 ~ p {found=1} END{exit !found}'; then
    _emit CRIT network_node_port_silent "Порт ${port} не слушает (связь с панелью оборвётся)" \
      "Проверь: ss -tlnp | grep :${port}"
    return
  fi
  _emit OK network_node_port_listen "Порт ${port} слушает" ""
}

check_network_panel_link() {
  local port="${NODE_PORT:-2222}" est
  est="$(ss -tn state established "( sport = :${port} )" 2>/dev/null | tail -n +2 | wc -l)"
  est="${est:-0}"

  local prev_zero_since
  prev_zero_since="$(state_get_int "network_panel_link_zero_since" 0)"

  if (( est == 0 )); then
    local now
    now=$(date +%s)
    if (( prev_zero_since == 0 )); then
      state_set "network_panel_link_zero_since" "$now"
    elif (( now - prev_zero_since >= 300 )); then
      _emit CRIT network_panel_link_lost "Нет established на :${port} в течение $(((now - prev_zero_since)/60)) мин" \
        "Панель не достукивается до ноды"
    fi
  else
    [[ "$prev_zero_since" != "0" ]] && state_set "network_panel_link_zero_since" "0"
    _emit OK network_panel_link "Established на :${port}: ${est}" ""
  fi
}

# Кворум из 3 источников — спасает от кэш-несогласованности и MitM на одном hop'е.
# Возвращает наиболее частый ответ (≥ 2 из 3), либо пусто если согласия нет.
_get_external_ip_quorum() {
  local sources=("https://ifconfig.io" "https://api.ipify.org" "https://icanhazip.com")
  local src r ips=""
  for src in "${sources[@]}"; do
    # || true — потому что под pipefail timeout/curl могут вернуть 124/22,
    # и pipe целиком вернёт non-zero → set -e убьёт функцию.
    r="$(timeout 5 curl -fsS --max-time 5 "$src" 2>/dev/null | head -1 | tr -d '[:space:]' || true)"
    if [[ "$r" =~ ^[0-9.]+$|^[0-9a-fA-F:]+$ ]]; then
      ips+="${r}"$'\n'
    fi
  done
  [[ -z "$ips" ]] && return 0
  printf '%s' "$ips" | sort | uniq -c | sort -rn | head -1 | awk '$1>=2 {print $2}' || true
}

check_network_external_ip() {
  local ip
  ip="$(_get_external_ip_quorum)"
  if [[ -z "$ip" ]]; then
    _emit OK network_external_ip "Внешний IP не определён (нет кворума источников)" ""
    return
  fi

  # Сравниваем с stable_ip — последним подтверждённым значением.
  # Кандидат становится stable только после 2 наблюдений подряд.
  local stable_ip candidate cand_count
  stable_ip="$(state_get "network_external_ip" "")"

  if [[ -z "$stable_ip" ]]; then
    state_set "network_external_ip" "$ip"
    _emit OK network_external_ip "Внешний IP: ${ip} (baseline)" ""
    return
  fi

  if [[ "$ip" == "$stable_ip" ]]; then
    state_unset "network_ip_candidate"
    state_unset "network_ip_candidate_count"
    _emit OK network_external_ip "Внешний IP: ${ip}" ""
    return
  fi

  candidate="$(state_get "network_ip_candidate" "")"
  cand_count="$(state_get_int "network_ip_candidate_count" 0)"

  if [[ "$candidate" == "$ip" ]]; then
    cand_count=$((cand_count + 1))
  else
    candidate="$ip"
    cand_count=1
  fi

  if (( cand_count >= 2 )); then
    state_set "network_external_ip" "$ip"
    state_unset "network_ip_candidate"
    state_unset "network_ip_candidate_count"
    _emit CRIT network_ip_changed "Внешний IP сменился: ${stable_ip} → ${ip}" \
      "Подтверждено ${cand_count} прогонами с кворумом 3 источников. Обнови IP в Settings → Nodes."
  else
    state_set "network_ip_candidate" "$candidate"
    state_set "network_ip_candidate_count" "$cand_count"
    _emit OK network_external_ip "IP кандидат: ${ip} (${cand_count}/2, stable=${stable_ip})" ""
  fi
}

check_network_ping() {
  local out loss rtt
  if ! out="$(timeout 6 ping -c 3 -W 1 1.1.1.1 2>/dev/null)"; then
    _emit WARN network_ping_failed "Ping 1.1.1.1 не прошёл (возможна сетевая проблема)" ""
    return
  fi
  loss="$(printf '%s' "$out" | awk -F',' '/packet loss/ {gsub(/[^0-9]/,"",$3); print $3}')"
  rtt="$(printf '%s' "$out" | awk -F'/' '/^rtt|^round-trip/ {print $5}')"
  if [[ -n "$loss" ]] && (( loss > 0 )); then
    _emit WARN network_ping_loss "Ping 1.1.1.1: потеря пакетов ${loss}%" "RTT avg=${rtt:-?}ms"
  elif [[ -n "$rtt" ]] && awk "BEGIN{exit !($rtt+0 > 200)}"; then
    _emit WARN network_ping_latency "Ping 1.1.1.1: RTT ${rtt}ms (> 200ms)" ""
  else
    _emit OK network_ping "Ping 1.1.1.1: RTT=${rtt:-?}ms loss=${loss:-0}%" ""
  fi
}

check_network_panel_health() {
  [[ -z "${EXTERNAL_PROBE_URL:-}" ]] && return 0
  local code
  code="$(timeout 6 curl -fsS -o /dev/null -w '%{http_code}' --max-time 5 "$EXTERNAL_PROBE_URL" 2>/dev/null || true)"
  if [[ "$code" != "200" ]]; then
    _emit CRIT network_panel_health "Панель ${EXTERNAL_PROBE_URL} вернула HTTP=${code:-no-response}" ""
  else
    _emit OK network_panel_health "Панель отвечает HTTP 200" ""
  fi
}

# ---------------------------------------------------------------------------
# 3.3 System
# ---------------------------------------------------------------------------

check_system_load() {
  local la1 cores
  la1="$(awk '{print $1}' /proc/loadavg)"
  cores="$(nproc 2>/dev/null || echo 1)"
  local threshold
  threshold="$(awk "BEGIN{print ${cores} * 1.5}")"
  if awk "BEGIN{exit !(${la1} > ${threshold})}"; then
    _emit WARN system_load_high "Load average 1m=${la1} (threshold $(printf '%.1f' "$threshold"), cores=${cores})" ""
  else
    _emit OK system_load "LA1=${la1} cores=${cores}" ""
  fi
}

check_system_memory() {
  local total avail used_pct
  total="$(awk '/^MemTotal:/{print $2}' /proc/meminfo)"
  avail="$(awk '/^MemAvailable:/{print $2}' /proc/meminfo)"
  used_pct="$(awk -v t="$total" -v a="$avail" 'BEGIN{printf "%.1f", 100*(t-a)/t}')"
  if awk "BEGIN{exit !(${used_pct} > ${THRESHOLD_RAM:-85})}"; then
    _emit WARN system_memory_high "RAM use: ${used_pct}% (порог ${THRESHOLD_RAM:-85}%)" \
      "Available: $((avail/1024)) MB"
  elif (( avail < 200000 )); then
    _emit WARN system_memory_low "Доступно RAM: $((avail/1024)) MB (< 200 MB)" ""
  else
    _emit OK system_memory "RAM use=${used_pct}% avail=$((avail/1024))MB" ""
  fi
}

check_system_disk() {
  local mp use
  # IFS=$' \t' внутри read обязателен: глобальный IFS=$'\n\t' (без пробела)
  # ломает word splitting и mp получает всю строку, use остаётся пустым.
  while IFS=$' \t' read -r mp use; do
    use="${use%\%}"
    [[ -z "$use" ]] && continue
    if (( use >= 95 )); then
      _emit CRIT system_disk_critical "Диск ${mp}: ${use}% (>95%)" \
        "Топ потребителей: см. du -sh ${mp}/* | sort -h | tail"
    elif (( use >= ${THRESHOLD_DISK:-85} )); then
      _emit WARN system_disk_high "Диск ${mp}: ${use}% (порог ${THRESHOLD_DISK:-85}%)" ""
    else
      _emit OK "system_disk_${mp}" "Диск ${mp}: ${use}%" ""
    fi
  done < <(df -P / /var/lib/docker 2>/dev/null | awk 'NR>1 && $1!="" {print $6, $5}' | sort -u)
}

check_system_inode() {
  local mp use
  while IFS=$' \t' read -r mp use; do
    use="${use%\%}"
    [[ -z "$use" ]] && continue
    if (( use >= 90 )); then
      _emit WARN system_inode_high "Inode ${mp}: ${use}%" ""
    fi
  done < <(df -i -P / /var/lib/docker 2>/dev/null | awk 'NR>1 && $1!="" && $5!="-" {print $6, $5}' | sort -u)
}

check_system_uptime() {
  local up_sec
  up_sec="$(awk '{print int($1)}' /proc/uptime)"
  if (( up_sec < 600 )); then
    _emit WARN system_uptime_short "Хост недавно перезагружался (uptime $((up_sec/60)) мин)" ""
  fi
  if [[ -f /var/run/reboot-required ]]; then
    _emit WARN system_reboot_required "Требуется перезагрузка после security-патча" \
      "$(cat /var/run/reboot-required.pkgs 2>/dev/null | head -3)"
  fi
}

# ---------------------------------------------------------------------------
# 3.4 Time
# ---------------------------------------------------------------------------

check_time_ntp() {
  local synced
  synced="$(timedatectl show -p NTPSynchronized --value 2>/dev/null)"
  if [[ "$synced" == "yes" ]]; then
    _emit OK time_ntp "NTP synced" ""
    return
  fi

  # Если у нас htpdate-fallback (провайдер блокирует и UDP/123, и TCP/443
  # к NTS-серверам) — NTPSynchronized всегда no, но время сверяется через
  # HTTPS Date раз в час. Это OK для нашей задачи (mTLS/JWT допуск ~минуты).
  local mode
  mode="$(state_get "hardening_ntp_managed" "")"
  if [[ "$mode" == "htpdate" ]]; then
    _emit OK time_ntp "Время через htpdate (HTTPS, провайдер блокирует NTP)" ""
    return
  fi

  _emit CRIT time_ntp_unsynced "NTP не синхронизировано (timedatectl: ${synced:-unknown})" \
    "mTLS/JWT с панелью сломаются. Починить: меню → 10 (Установить NTP)"
}

check_time_offset() {
  command -v chronyc >/dev/null 2>&1 || return 0
  local offset
  offset="$(chronyc tracking 2>/dev/null | awk '/Last offset/ {print $4}')"
  [[ -z "$offset" ]] && return 0
  # offset в секундах; берём абсолютное значение
  local abs
  abs="$(awk -v o="$offset" 'BEGIN{print (o<0 ? -o : o)}')"
  if awk "BEGIN{exit !(${abs} > 30)}"; then
    _emit CRIT time_offset_large "Смещение времени: ${offset}s (> 30s)" ""
  fi
}

# ---------------------------------------------------------------------------
# 3.5 Certificates
# ---------------------------------------------------------------------------

check_certs() {
  local key_b64 json node_cert ca_cert
  # Убираем префикс SECRET_KEY= и опциональные обёрточные кавычки
  # (в docker-compose.yml часто пишут SECRET_KEY="eyJ..." — кавычки попадают в env).
  key_b64="$(_jq_inspect '.Config.Env[] | select(startswith("SECRET_KEY="))' \
             | sed -e 's/^SECRET_KEY=//' -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//" || true)"
  if [[ -z "$key_b64" ]]; then
    _emit OK certs_skipped "SECRET_KEY не найден в env контейнера" ""
    return
  fi
  secrets_register "$key_b64"

  if ! json="$(printf '%s' "$key_b64" | base64 -d 2>/dev/null)"; then
    _emit WARN certs_decode_failed "Не удалось декодировать SECRET_KEY (base64)" ""
    return
  fi

  node_cert="$(printf '%s' "$json" | jq -r '.nodeCertPem // empty' 2>/dev/null)"
  ca_cert="$(printf '%s' "$json" | jq -r '.caCertPem // empty' 2>/dev/null)"

  _check_one_cert "node" "$node_cert"
  _check_one_cert "ca"   "$ca_cert"

  # Хеш SECRET_KEY для детекта ротации (без логирования значения)
  local hash prev_hash
  hash="$(printf '%s' "$key_b64" | sha256sum | awk '{print $1}')"
  prev_hash="$(state_get "secret_key_hash" "$hash")"
  state_set "secret_key_hash" "$hash"
  if [[ -n "$prev_hash" && "$prev_hash" != "$hash" ]]; then
    _emit INFO certs_secret_rotated "SECRET_KEY ноды был ротирован" \
      "Хеш изменился (значение не логируется)"
  fi
}

_check_one_cert() {
  local label="$1" pem="$2"
  [[ -z "$pem" ]] && return 0
  local enddate exp now days
  enddate="$(printf '%s' "$pem" | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)"
  [[ -z "$enddate" ]] && {
    _emit WARN "certs_${label}_unparseable" "Не удалось прочитать дату ${label}-сертификата" ""
    return
  }
  exp="$(_to_unix "$enddate")"
  now="$(date +%s)"
  days=$(( (exp - now) / 86400 ))
  state_set "cert_${label}_days_left" "$days"
  if (( days < 0 )); then
    _emit CRIT "certs_${label}_expired" "Сертификат (${label}) истёк ${enddate}" ""
  elif (( days < 7 )); then
    _emit CRIT "certs_${label}_expiring" "Сертификат (${label}) истекает через ${days} дн." \
      "Перевыпусти через панель: Nodes → ${NODE_NAME:-this} → Regenerate"
  elif (( days < 30 )); then
    _emit WARN "certs_${label}_expiring" "Сертификат (${label}) истекает через ${days} дн." ""
  else
    _emit OK "certs_${label}" "Сертификат (${label}): ${days} дн. до истечения" ""
  fi
}

# ---------------------------------------------------------------------------
# 3.6 Logs
# ---------------------------------------------------------------------------

check_logs() {
  local since now last
  now="$(date +%s)"
  last="$(state_get_int "logs_last_run_unix" "$((now - 300))")"
  state_set "logs_last_run_unix" "$now"
  since="$(date -u -d "@${last}" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null)"
  [[ -z "$since" ]] && return 0

  local logs
  logs="$(timeout 5 docker logs "$REMNANODE_CONTAINER" --since="$since" 2>&1 || true)"
  [[ -z "$logs" ]] && return 0

  # tls: уточнён — иначе ловит info-логи нормальных handshake'ов.
  local errors
  errors="$(printf '%s\n' "$logs" | grep -E -i 'ERROR|FATAL|panic|tls.*(error|fail|handshake failure)|address already in use' | head -5 || true)"
  if [[ -n "$errors" ]]; then
    _emit WARN logs_errors_present "В логах remnanode появились ERROR/FATAL/tls:" "$errors"
  fi
}

# ---------------------------------------------------------------------------
# 3.7 Security
# ---------------------------------------------------------------------------

# check_security_open_ports — удалён (дублировал ports_drift_check для xray-портов).
# Если на ноде нужен мониторинг открытых портов вне xray (например, кто-то поднял
# nginx) — добавь их в EXTRA_PORTS_WHITELIST или пропиши свою проверку.

check_security_ufw() {
  if ! command -v ufw >/dev/null 2>&1; then
    _emit WARN security_ufw_missing "ufw не установлен" "Hardening не выполнен — запусти install.sh"
    return
  fi
  local status
  status="$(ufw status 2>/dev/null | head -1)"
  if [[ "$status" != *"active"* ]]; then
    _emit CRIT security_ufw_disabled "UFW disabled (${status})" \
      "Файервол выключен — все порты открыты. sudo ufw enable"
  else
    _emit OK security_ufw "UFW active" ""
  fi
}

check_security_fail2ban() {
  if ! systemctl is-active --quiet fail2ban 2>/dev/null; then
    _emit WARN security_fail2ban_inactive "fail2ban не запущен" "sudo systemctl start fail2ban"
    return
  fi
  _emit OK security_fail2ban "fail2ban active" ""
}

check_security_failed_ssh() {
  command -v journalctl >/dev/null 2>&1 || return 0
  # journalctl -g фильтрует на уровне journald (быстрее чем bash grep).
  local raw filtered count admin_filter
  raw="$(timeout 5 journalctl _COMM=sshd --since "1 hour ago" -g 'Failed password' --no-pager 2>/dev/null || true)"
  if [[ -n "${SSH_ADMIN_IPS:-}" ]]; then
    admin_filter="$(printf '%s' "$SSH_ADMIN_IPS" | tr ',' '|' | sed 's/[][\\.]/\\&/g')"
    filtered="$(printf '%s\n' "$raw" | grep -Ev " from (${admin_filter}) " || true)"
  else
    filtered="$raw"
  fi
  count="$(printf '%s\n' "$filtered" | grep -c . || true)"
  count="${count:-0}"
  if (( count > 30 )); then
    # awk вытаскивает IP после слова "from"; sort | uniq -c | sort -rn → топ-3.
    local top
    top="$(printf '%s\n' "$filtered" \
      | awk '{for(i=1;i<=NF;i++) if($i=="from"){print $(i+1); break}}' \
      | sort | uniq -c | sort -rn | head -3 \
      | awk '{printf "  %s × %s\n", $1, $2}' || true)"
    [[ -z "$top" ]] && top="(не удалось извлечь IP из journalctl)"
    _emit WARN security_ssh_brute "Неудачных SSH-логинов за час: ${count}" "Топ источников:"$'\n'"${top}"
  fi
}

# NB: на первом запуске baseline = текущее состояние, поэтому
# пользователей, добавленных ДО установки агента, мы не зафиксируем как «новых».
# Это особенность: алертим только на изменения после baseline.
check_security_users() {
  local current prev added
  current="$(awk -F: '$3>=1000 && $1!="nobody" {print $1}' /etc/passwd | sort | paste -sd, - || true)"
  prev="$(state_get "known_users_csv" "$current")"
  state_set "known_users_csv" "$current"
  if [[ "$prev" != "$current" ]]; then
    added="$(comm -13 <(printf '%s' "$prev" | tr ',' '\n' | sort -u) <(printf '%s' "$current" | tr ',' '\n' | sort -u) | paste -sd, -)"
    if [[ -n "$added" ]]; then
      _emit CRIT security_new_user "Новый пользователь в /etc/passwd: ${added}" \
        "Это вы добавили? awk -F: '\$3>=1000' /etc/passwd"
    fi
  fi
}

# ---------------------------------------------------------------------------
# 3.8 Integrity
# ---------------------------------------------------------------------------

check_integrity_compose_hash() {
  [[ -f "$REMNANODE_COMPOSE" ]] || return 0
  local hash prev
  hash="$(sha256sum "$REMNANODE_COMPOSE" | awk '{print $1}')"
  prev="$(state_get "compose_hash" "$hash")"
  state_set "compose_hash" "$hash"
  if [[ "$prev" != "$hash" ]]; then
    _emit WARN integrity_compose_changed "Изменился ${REMNANODE_COMPOSE}" \
      "SHA256: ${prev:0:12}… → ${hash:0:12}… (это вы или кто-то ещё?)"
  fi
}

# Зовётся только из daily_summary, не каждые 2 минуты:
#  - docker manifest inspect анонимный — лимит Docker Hub 200 запросов / 6ч на IP
#  - чтобы не спамить алертами «доступно обновление» — алертит только при смене remote digest
check_integrity_image_update() {
  command -v docker >/dev/null 2>&1 || return 0
  local manifest local_id last_seen
  manifest="$(timeout 10 docker manifest inspect "$REMNANODE_IMAGE" 2>/dev/null \
    | jq -r '.config.digest // .manifests[0].digest // empty' 2>/dev/null)"
  [[ -z "$manifest" ]] && return 0
  local_id="$(_jq_inspect '.Image')"
  if [[ -n "$local_id" && -n "$manifest" && "$local_id" != "$manifest" ]]; then
    last_seen="$(state_get "image_last_seen_remote" "")"
    if [[ "$last_seen" != "$manifest" ]]; then
      _emit WARN integrity_image_outdated "Доступно обновление ${REMNANODE_IMAGE}" \
        "Текущий: ${local_id:0:19}… Новый: ${manifest:0:19}… Обновить: cd /opt/remnanode && docker compose pull && docker compose up -d"
      state_set "image_last_seen_remote" "$manifest"
    fi
  else
    state_unset "image_last_seen_remote"
  fi
}

# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

# checks_run_all — выполняет все проверки последовательно. Печатает SEV|key|msg|details строки.
checks_run_all() {
  state_init

  check_container
  check_network_listen
  check_network_panel_link
  check_network_external_ip
  check_network_ping
  check_network_panel_health

  check_system_load
  check_system_memory
  check_system_disk
  check_system_inode
  check_system_uptime

  check_time_ntp
  check_time_offset

  check_certs
  check_logs

  check_security_ufw
  check_security_fail2ban
  check_security_failed_ssh
  check_security_users

  check_integrity_compose_hash
  # check_integrity_image_update — НЕ в основном цикле, зовётся из daily_summary
  # (docker manifest inspect имеет rate-limit Docker Hub: 200/6ч анонимно).

  # Port drift detection — из lib/ports.sh
  if declare -F ports_drift_check >/dev/null; then
    ports_drift_check
  fi
}
