#!/usr/bin/env bash
# lib/notify.sh — Telegram-нотификатор.
#
# Контракт:
#   notify_dispatch_results <multiline-string SEV|key|msg|details>
#     — главная точка входа из audit.sh для одного прогона.
#       Применяет cooldown, шлёт CRIT/WARN/INFO, генерирует RECOVERY для
#       ключей которые отправлялись ранее, но в текущем прогоне их нет.
#
#   notify_test_message
#     — тестовое сообщение для --test-notify (не аффектит cooldown/state).
#
#   notify_drain_queue
#     — попытаться отправить накопившиеся сообщения из offline queue.
#
# Хранилища:
#   /var/lib/remnawave-audit/queue/<unix>.<rand>.json — offline очередь FIFO.
#   /var/log/remnawave-audit/alerts.log — JSON-строки на каждое сообщение.
#   state.json:
#     alert_last_sent_<key> = unix_ts
#     notified_keys = CSV ключей с активным алертом (для recovery)

readonly QUEUE_DIR="${STATE_DIR:-/var/lib/remnawave-audit}/queue"
readonly LOG_FILE="${LOG_DIR:-/var/log/remnawave-audit}/alerts.log"
readonly TG_API="https://api.telegram.org"
readonly MSG_MAX=3800       # запас от лимита Telegram 4096
readonly QUEUE_MAX=100      # старые удаляются
readonly QUEUE_DRAIN_BATCH=50
readonly RECOVERY_HYSTERESIS=3   # ключ должен исчезнуть N подряд раз перед ✅

# ---------------------------------------------------------------------------
# Init
# ---------------------------------------------------------------------------

notify_init() {
  mkdir -p "$QUEUE_DIR" "$(dirname "$LOG_FILE")"
  [[ -f "$LOG_FILE" ]] || { : >"$LOG_FILE"; chmod 640 "$LOG_FILE"; }
}

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# Перевод технического ключа алерта в человеко-понятный заголовок (русский).
# Используется в recovery-сообщениях: вместо "Recovered: ports_inbound_silent_8388"
# покажем "✅ Инбаунд tcp/8388 снова работает".
_humanize_key() {
  local key="$1"
  case "$key" in
    container_missing)            printf 'Контейнер remnanode восстановлен' ;;
    container_status)             printf 'Контейнер remnanode снова running' ;;
    container_unhealthy)          printf 'Контейнер remnanode healthy' ;;
    container_restarted)          printf 'Контейнер стабилен (без рестартов)' ;;
    container_cpu_high)           printf 'CPU контейнера в норме' ;;
    container_ram_high)           printf 'RAM контейнера в норме' ;;

    network_node_port_silent)     printf 'Порт связи с панелью снова слушает' ;;
    network_panel_link_lost)      printf 'Связь с панелью восстановлена' ;;
    network_ip_changed)           printf 'Внешний IP стабилизировался' ;;
    network_ping_failed)          printf 'Сеть восстановлена' ;;
    network_ping_loss)            printf 'Потери пакетов прекратились' ;;
    network_ping_latency)         printf 'Сетевая задержка в норме' ;;
    network_panel_health)         printf 'Панель снова отвечает' ;;

    system_load_high)             printf 'Нагрузка CPU в норме' ;;
    system_memory_high|system_memory_low)
                                  printf 'RAM в норме' ;;
    system_disk_critical|system_disk_high)
                                  printf 'Место на диске освободилось' ;;
    system_inode_high)            printf 'Inode в норме' ;;
    system_uptime_short)          printf 'Хост стабильно работает' ;;
    system_reboot_required)       printf 'Хост перезагружен после security-патча' ;;

    time_ntp_unsynced)            printf 'Время синхронизировано через NTP' ;;
    time_offset_large)            printf 'Смещение времени в норме' ;;

    certs_*_expiring|certs_*_expired|certs_decode_failed|certs_*_unparseable)
                                  printf 'Сертификаты в порядке' ;;

    logs_errors_present)          printf 'Новых ошибок в логах remnanode нет' ;;

    security_ufw_disabled|security_ufw_missing)
                                  printf 'UFW снова активен' ;;
    security_fail2ban_inactive)   printf 'fail2ban снова активен' ;;
    security_ssh_brute)           printf 'SSH-брутфорс прекратился' ;;
    security_unknown_ports)       printf 'Лишних открытых портов нет' ;;

    integrity_compose_changed)    printf 'docker-compose.yml не менялся' ;;
    integrity_image_outdated)     printf 'Образ ноды обновлён' ;;

    ports_node_port_drift)        printf 'NODE_PORT синхронизирован' ;;
    ports_node_port_blocked)      printf 'UFW снова пропускает NODE_PORT' ;;
    ports_unknown_listening_*)
                                  printf 'Порт %s включён в whitelist' "${key#ports_unknown_listening_}" ;;
    ports_inbound_silent_*)
                                  printf 'Инбаунд tcp/%s снова слушает' "${key#ports_inbound_silent_}" ;;

    *)                            printf 'Алерт снят: %s' "$key" ;;
  esac
}

# HTML-escape для Telegram parse_mode=HTML.
_html_escape() {
  printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'
}

# Обрезание длинного текста с пометкой.
_truncate() {
  local s="$1" max="${2:-$MSG_MAX}"
  if (( ${#s} > max )); then
    printf '%s\n…[truncated %d chars]' "${s:0:max}" "$((${#s} - max))"
  else
    printf '%s' "$s"
  fi
}

# Префикс заголовка: эмодзи + [NODE_NAME / IP].
_severity_prefix() {
  local sev="$1"
  case "$sev" in
    CRIT)     printf '🔴' ;;
    WARN)     printf '🟡' ;;
    INFO)     printf '🟢' ;;
    RECOVERY) printf '✅' ;;
    *)        printf 'ℹ️' ;;
  esac
}

# Заголовок: "[NODE_NAME / 1.2.3.4]" или "[NODE_NAME]" если IP не известен.
_node_tag() {
  local ip
  ip="$(state_get "network_external_ip" "")"
  if [[ -n "$ip" ]]; then
    printf '%s / %s' "${NODE_NAME:-node}" "$ip"
  else
    printf '%s' "${NODE_NAME:-node}"
  fi
}

# _format_message <sev> <msg> <details>
# Возвращает готовый HTML-текст.
_format_message() {
  local sev="$1" msg="$2" details="$3"
  local prefix tag header body
  prefix="$(_severity_prefix "$sev")"
  tag="$(_html_escape "$(_node_tag)")"
  header="$(_html_escape "$msg")"
  body=""
  if [[ -n "$details" ]]; then
    body="$(_html_escape "$(_truncate "$details")")"
    body=$'\n'"<code>${body}</code>"
  fi
  printf '%s [%s]\n<b>%s</b>%s' "$prefix" "$tag" "$header" "$body"
}

# Локальный лог (одна JSON-строка на сообщение).
_notify_log_local() {
  local sev="$1" key="$2" msg="$3"
  notify_init
  local ts
  ts="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  jq -nc --arg ts "$ts" --arg sev "$sev" --arg key "$key" --arg msg "$msg" \
    --arg node "${NODE_NAME:-}" \
    '{ts:$ts, sev:$sev, key:$key, node:$node, msg:$msg}' \
    >> "$LOG_FILE" 2>/dev/null || true
}

# Curl до Telegram. Возвращает:
#   0 — успех
#   1 — сетевая ошибка (надо в очередь)
#   2 — Telegram отверг (например неверный chat_id) — НЕ повторять
_notify_curl() {
  local chat_id="$1" text="$2"
  local rc=0
  curl -fsS --max-time 10 \
    -d "chat_id=${chat_id}" \
    -d "parse_mode=HTML" \
    -d "disable_web_page_preview=true" \
    --data-urlencode "text=${text}" \
    "${TG_API}/bot${BOT_TOKEN}/sendMessage" >/dev/null 2>&1 || rc=$?
  case "$rc" in
    0)            return 0 ;;
    6|7|28|35|56) return 1 ;;  # network: resolve/connect/timeout/ssl
    *)
      log_warn "Telegram rejected (curl rc=${rc}) chat_id=${chat_id}"
      return 2
      ;;
  esac
}

# Сохранить сообщение в offline очередь.
_notify_enqueue() {
  local chat_id="$1" text="$2"
  notify_init
  local fname
  fname="${QUEUE_DIR}/$(date +%s).$$.$RANDOM.json"
  jq -nc --arg c "$chat_id" --arg t "$text" '{chat_id:$c, text:$t}' > "$fname" 2>/dev/null \
    || log_warn "Failed to enqueue notification"
}

# Отправить или поставить в очередь — для всех ADMIN_CHAT_ID.
_notify_emit() {
  local sev="$1" key="$2" msg="$3" details="$4"
  details="${details//$'\x01'/$'\n'}"
  local text
  text="$(_format_message "$sev" "$msg" "$details")"

  _notify_log_local "$sev" "$key" "$msg"

  if [[ "${DRY_RUN:-0}" == "1" ]]; then
    log_info "[dry-run] would send: ${sev} ${key}"
    printf '%s\n' "$text"
    return 0
  fi

  local chat_id rc
  local IFS=','
  for chat_id in $ADMIN_CHAT_ID; do
    [[ -z "$chat_id" ]] && continue
    rc=0
    _notify_curl "$chat_id" "$text" || rc=$?
    case "$rc" in
      0) : ;;                                # OK
      1) _notify_enqueue "$chat_id" "$text" ;;  # network → queue
      2) : ;;                                # Telegram отверг — пропускаем
    esac
  done
  unset IFS
}

# Решить, можно ли слать данный ключ (cooldown).
_notify_should_send() {
  local sev="$1" key="$2" cooldown last_sent now
  case "$sev" in
    CRIT) cooldown="${COOLDOWN_CRITICAL_SEC:-900}" ;;
    WARN) cooldown="${COOLDOWN_WARNING_SEC:-3600}" ;;
    *)    return 0 ;;
  esac
  last_sent="$(state_get_int "alert_last_sent_${key}" 0)"
  now="$(date +%s)"
  (( now - last_sent >= cooldown ))
}

# ---------------------------------------------------------------------------
# Public: dispatch_results
# ---------------------------------------------------------------------------

# notify_dispatch_results <multiline string with SEV|key|msg|details>
notify_dispatch_results() {
  notify_init
  local results="$1"

  local active_now=""
  local sev key msg details
  while IFS='|' read -r sev key msg details; do
    [[ -z "$sev" ]] && continue
    case "$sev" in
      CRIT|WARN)
        active_now+="${key},"
        if _notify_should_send "$sev" "$key"; then
          _notify_emit "$sev" "$key" "$msg" "$details"
          state_set "alert_last_sent_${key}" "$(date +%s)"
        fi
        ;;
      INFO)
        _notify_emit "$sev" "$key" "$msg" "$details"
        ;;
      OK|RECOVERY)
        : ;;
    esac
  done <<<"$results"

  # Recovery с hysteresis: ключ должен исчезнуть RECOVERY_HYSTERESIS раз подряд.
  # Это защищает от флапа (например CPU около порога 80%): без задержки
  # каждый цикл порождал бы пару 🔴+✅ → 60 сообщений в час.
  local prev_keys k cnt
  prev_keys="$(state_get "notified_keys" "")"
  if [[ -n "$prev_keys" ]]; then
    local IFS=','
    for k in $prev_keys; do
      [[ -z "$k" ]] && continue
      if printf ',%s,' "$active_now" | grep -q ",${k},"; then
        # Ключ всё ещё активен — сбрасываем счётчик recovery.
        state_unset "recovery_count_${k}"
      else
        cnt="$(state_get_int "recovery_count_${k}" 0)"
        cnt=$((cnt + 1))
        if (( cnt >= RECOVERY_HYSTERESIS )); then
          _notify_emit "RECOVERY" "$k" "$(_humanize_key "$k")" ""
          state_unset "alert_last_sent_${k}"
          state_unset "recovery_count_${k}"
        else
          state_set "recovery_count_${k}" "$cnt"
          # Пока не recovery — оставляем в notified, чтобы следующий цикл считал.
          active_now+="${k},"
        fi
      fi
    done
    unset IFS
  fi
  state_set "notified_keys" "${active_now%,}"

  notify_drain_queue
}

# ---------------------------------------------------------------------------
# Public: drain queue
# ---------------------------------------------------------------------------

notify_drain_queue() {
  notify_init
  [[ -d "$QUEUE_DIR" ]] || return 0

  local f sent=0
  while IFS= read -r f; do
    [[ -f "$f" ]] || continue
    local chat_id text rc=0
    chat_id="$(jq -r '.chat_id // empty' "$f" 2>/dev/null)"
    text="$(jq -r '.text // empty' "$f" 2>/dev/null)"
    if [[ -z "$chat_id" || -z "$text" ]]; then
      rm -f "$f"
      continue
    fi
    _notify_curl "$chat_id" "$text" || rc=$?
    case "$rc" in
      0) rm -f "$f"; sent=$((sent+1)) ;;
      1) break ;;          # сети всё ещё нет — стоп
      2) rm -f "$f" ;;     # отвергнуто Telegram'ом — выбрасываем, не циклить
    esac
  done < <(find "$QUEUE_DIR" -maxdepth 1 -type f -name '*.json' -printf '%T@ %p\n' \
            | sort -n | head -n "$QUEUE_DRAIN_BATCH" | awk '{print $2}')

  (( sent > 0 )) && log_info "queue drained: ${sent} messages sent"

  # Trim переполненной очереди (FIFO).
  local total
  total="$(find "$QUEUE_DIR" -maxdepth 1 -type f -name '*.json' | wc -l)"
  if (( total > QUEUE_MAX )); then
    local trim=$((total - QUEUE_MAX))
    find "$QUEUE_DIR" -maxdepth 1 -type f -name '*.json' -printf '%T@ %p\n' \
      | sort -n | head -n "$trim" | awk '{print $2}' | xargs -r rm -f
    log_warn "queue overflow: trimmed ${trim} oldest messages"
  fi
}

# ---------------------------------------------------------------------------
# Public: test message
# ---------------------------------------------------------------------------

notify_test_message() {
  notify_init
  local text
  text="$(printf '✅ <b>Test from %s</b>\nВерсия: %s\nВремя: %s' \
    "$(_html_escape "${NODE_NAME:-node}")" \
    "${VERSION:-?}" \
    "$(date '+%Y-%m-%d %H:%M:%S %Z')")"

  if [[ "${DRY_RUN:-0}" == "1" ]]; then
    log_info "[dry-run] test message:"
    printf '%s\n' "$text"
    return 0
  fi

  local chat_id rc=0 ok=0 fail=0
  local IFS=','
  for chat_id in $ADMIN_CHAT_ID; do
    [[ -z "$chat_id" ]] && continue
    rc=0
    _notify_curl "$chat_id" "$text" || rc=$?
    if (( rc == 0 )); then
      ok=$((ok+1))
    else
      fail=$((fail+1))
      log_warn "test send failed for chat_id=${chat_id} rc=${rc}"
    fi
  done
  unset IFS
  log_info "test sent: ok=${ok} fail=${fail}"
  (( fail == 0 ))
}
