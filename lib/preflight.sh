#!/usr/bin/env bash
# lib/preflight.sh — sanity checks ДО любых изменений в системе.
#
# Контракт: preflight_run [--force] [--bot-token=...]
#   Печатает по строке на проверку. В конце — общий статус.
#   Возвращает 0 если можно продолжать, 1 при фатале.
#
# Грейды:
#   FATAL  — abort install.sh
#   WARN   — продолжаем, но предупреждаем (или abort если --strict)
#   OK     — норм
#
# Каждая проверка не имеет побочных эффектов (read-only).

readonly REMNANODE_COMPOSE_DEFAULT="/opt/remnanode/docker-compose.yml"

_PF_FATALS=0
_PF_WARNS=0
_PF_FORCE=0

_pf_emit() {
  local grade="$1" msg="$2"
  case "$grade" in
    OK)    printf '  ✓  %s\n' "$msg" ;;
    WARN)  printf '  ⚠  %s\n' "$msg"; _PF_WARNS=$((_PF_WARNS+1)) ;;
    FATAL) printf '  ✗  %s\n' "$msg"; _PF_FATALS=$((_PF_FATALS+1)) ;;
  esac
}

# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

preflight_check_root() {
  if (( EUID == 0 )); then
    _pf_emit OK "Запущено от root"
  else
    _pf_emit FATAL "Не root. Запусти через sudo."
  fi
}

preflight_check_os() {
  if [[ ! -f /etc/os-release ]]; then
    _pf_emit WARN "/etc/os-release отсутствует — не могу определить ОС"
    return
  fi
  # shellcheck disable=SC1091
  . /etc/os-release
  local id="${ID:-unknown}" ver="${VERSION_ID:-unknown}"
  if [[ "$id" == "ubuntu" && "$ver" =~ ^(22\.04|24\.04)$ ]]; then
    _pf_emit OK "ОС: Ubuntu ${ver}"
  else
    if (( _PF_FORCE == 1 )); then
      _pf_emit WARN "ОС: ${id} ${ver} (не Ubuntu 22.04/24.04, но --force указан)"
    else
      _pf_emit FATAL "ОС: ${id} ${ver}. Поддерживается только Ubuntu 22.04/24.04. Используй --force чтобы продолжить."
    fi
  fi
}

preflight_check_required_cmds() {
  local missing=()
  local cmd
  for cmd in bash curl jq openssl ss awk sed grep; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing+=("$cmd")
    fi
  done
  if (( ${#missing[@]} == 0 )); then
    _pf_emit OK "Утилиты на месте: bash curl jq openssl ss awk sed grep"
  else
    _pf_emit FATAL "Не установлены: ${missing[*]}. Поставь: apt install -y ${missing[*]}"
  fi
}

preflight_check_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    _pf_emit FATAL "docker не установлен. Сначала разверни ноду: https://docs.rw/docs/install/remnawave-node"
    return
  fi
  if ! docker info >/dev/null 2>&1; then
    _pf_emit FATAL "docker установлен, но daemon недоступен (systemctl status docker)"
    return
  fi
  _pf_emit OK "docker daemon доступен"
}

preflight_check_remnanode() {
  local compose="${REMNANODE_COMPOSE:-$REMNANODE_COMPOSE_DEFAULT}"
  if [[ ! -f "$compose" ]]; then
    _pf_emit FATAL "${compose} не найден. Установлена ли нода Remnawave? https://docs.rw/docs/install/remnawave-node"
    return
  fi
  if ! grep -q 'remnawave/node' "$compose"; then
    _pf_emit FATAL "${compose} не содержит образа remnawave/node — это не нода Remnawave"
    return
  fi
  _pf_emit OK "${compose} существует и содержит remnawave/node"

  # Контейнер созданhi or нет (warn-only)
  if docker inspect "${REMNANODE_CONTAINER:-remnanode}" >/dev/null 2>&1; then
    _pf_emit OK "Контейнер ${REMNANODE_CONTAINER:-remnanode} создан"
  else
    _pf_emit WARN "Контейнер ${REMNANODE_CONTAINER:-remnanode} не создан (cd /opt/remnanode && docker compose up -d)"
  fi
}

preflight_check_disk_space() {
  local avail_kb avail_mb
  avail_kb="$(df -P / | awk 'NR==2 {print $4}')"
  avail_mb=$((avail_kb / 1024))
  if (( avail_mb < 1024 )); then
    _pf_emit FATAL "На / меньше 1 GB свободно (${avail_mb} MB). Освободи место."
  else
    _pf_emit OK "На / свободно: $((avail_mb / 1024)) GB"
  fi
}

preflight_check_sshd_port() {
  local p
  p="$(awk '/^[Pp]ort /{print $2; exit}' /etc/ssh/sshd_config 2>/dev/null)"
  p="${p:-22}"
  if [[ ! "$p" =~ ^[0-9]+$ ]] || (( p < 1 || p > 65535 )); then
    _pf_emit FATAL "Не удалось распарсить SSH-порт из /etc/ssh/sshd_config: '${p}'"
    return
  fi
  if ! ss -tln 2>/dev/null | awk -v port=":${p}$" '$4 ~ port {found=1} END{exit !found}'; then
    _pf_emit WARN "sshd_config Port=${p}, но ss не видит ${p} среди слушающих (sshd запущен?)"
    return
  fi
  _pf_emit OK "SSH-порт: ${p} (sshd слушает)"
}

preflight_check_telegram_api() {
  local code
  code="$(curl -fsS -o /dev/null -w '%{http_code}' --max-time 5 https://api.telegram.org 2>/dev/null || true)"
  # api.telegram.org / без токена возвращает 404 — это нормально, главное что сеть есть
  case "$code" in
    200|400|404) _pf_emit OK "api.telegram.org доступен (HTTP ${code})" ;;
    "")          _pf_emit WARN "api.telegram.org недоступен (нет ответа). Установка продолжится — алерты осядут в очереди" ;;
    *)           _pf_emit WARN "api.telegram.org вернул HTTP ${code} — необычно, но не блокирует" ;;
  esac
}

# preflight_check_bot_token <token>
# Если токен не передан или пустой — проверка пропускается с WARN.
preflight_check_bot_token() {
  local token="${1:-}"
  if [[ -z "$token" ]]; then
    _pf_emit WARN "BOT_TOKEN не передан в preflight — пропускаю валидацию"
    return
  fi
  if [[ ! "$token" =~ ^[0-9]+:[A-Za-z0-9_-]{30,}$ ]]; then
    _pf_emit FATAL "BOT_TOKEN формат неверен (ожидается '<digits>:<base64-ish>')"
    return
  fi
  secrets_register "$token"
  local resp
  resp="$(curl -fsS --max-time 8 "https://api.telegram.org/bot${token}/getMe" 2>/dev/null || true)"
  if [[ -z "$resp" ]]; then
    _pf_emit WARN "getMe не ответил (сеть). Установка продолжится."
    return
  fi
  if printf '%s' "$resp" | jq -e '.ok == true' >/dev/null 2>&1; then
    local username
    username="$(printf '%s' "$resp" | jq -r '.result.username')"
    _pf_emit OK "BOT_TOKEN валиден (бот: @${username})"
  else
    _pf_emit FATAL "Telegram getMe отверг токен: $(printf '%s' "$resp" | jq -r '.description // "unknown error"')"
  fi
}

# Предупреждение про bridge-контейнеры — UFW их не защищает.
preflight_check_docker_bridges() {
  command -v docker >/dev/null 2>&1 || return 0
  local names
  names="$(docker ps --format '{{.Names}}' 2>/dev/null | while read -r name; do
    [[ -z "$name" || "$name" == "${REMNANODE_CONTAINER:-remnanode}" ]] && continue
    local mode
    mode="$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$name" 2>/dev/null || true)"
    if [[ "$mode" == "default" || "$mode" == "bridge" ]]; then
      printf '%s ' "$name"
    fi
  done)"
  names="${names% }"
  if [[ -n "$names" ]]; then
    _pf_emit WARN "Bridge-контейнеры: ${names}. UFW их не фильтрует (Docker правит iptables в обход UFW)"
  else
    _pf_emit OK "Bridge-контейнеров помимо ноды нет — UFW защищает хост корректно"
  fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

# preflight_run [--force] [--bot-token=<token>]
preflight_run() {
  _PF_FATALS=0
  _PF_WARNS=0
  _PF_FORCE=0
  local bot_token=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --force)        _PF_FORCE=1 ;;
      --bot-token=*)  bot_token="${1#--bot-token=}" ;;
    esac
    shift
  done

  printf '\n=== Pre-flight checks ===\n'
  preflight_check_root
  preflight_check_os
  preflight_check_required_cmds
  preflight_check_docker
  preflight_check_remnanode
  preflight_check_disk_space
  preflight_check_sshd_port
  preflight_check_telegram_api
  preflight_check_bot_token "$bot_token"
  preflight_check_docker_bridges

  printf '\n'
  if (( _PF_FATALS > 0 )); then
    log_error "Pre-flight: ${_PF_FATALS} фатальных проблем, ${_PF_WARNS} предупреждений. Установка прервана."
    return 1
  fi
  log_info "Pre-flight: ОК (${_PF_WARNS} warnings)"
  return 0
}
