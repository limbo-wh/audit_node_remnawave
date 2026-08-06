#!/usr/bin/env bash
# lib/hardening.sh — UFW + fail2ban + unattended-upgrades + backup/rollback.
#
# Все функции идемпотентны: повторный запуск приводит к тому же состоянию.
# Перед изменениями делается snapshot в /var/lib/remnawave-audit/backup/<ts>/.
#
# НЕ трогает sshd_config (только бэкапит для сверки).
# НЕ перезагружает хост.

readonly HARDENING_BACKUP_ROOT="${STATE_DIR:-/var/lib/remnawave-audit}/backup"
readonly HARDENING_BACKUP_KEEP=5

# Корень конфигов fail2ban — переопределяется для тестов, как REMNANODE_COMPOSE.
: "${FAIL2BAN_DIR:=/etc/fail2ban}"
readonly FAIL2BAN_JAIL_FILE="${FAIL2BAN_DIR}/jail.d/remnawave-audit.local"
readonly UNATTENDED_FILE="/etc/apt/apt.conf.d/50unattended-upgrades"
readonly AUTO_UPGRADES_FILE="/etc/apt/apt.conf.d/20auto-upgrades"

# ---------------------------------------------------------------------------
# Backup
# ---------------------------------------------------------------------------

hardening_backup() {
  mkdir -p "$HARDENING_BACKUP_ROOT"
  local ts d
  ts="$(date +%Y%m%d-%H%M%S)"
  d="${HARDENING_BACKUP_ROOT}/${ts}"
  mkdir -p "$d"

  iptables-save  > "${d}/iptables.rules"  2>/dev/null || true
  ip6tables-save > "${d}/ip6tables.rules" 2>/dev/null || true
  if command -v ufw >/dev/null 2>&1; then
    ufw status verbose > "${d}/ufw-status.txt" 2>/dev/null || true
  fi
  [[ -d /etc/fail2ban ]] && cp -r /etc/fail2ban "${d}/fail2ban" 2>/dev/null || true
  [[ -f /etc/ssh/sshd_config ]] && cp /etc/ssh/sshd_config "${d}/sshd_config" 2>/dev/null || true
  [[ -f "$UNATTENDED_FILE"   ]] && cp "$UNATTENDED_FILE"   "${d}/" 2>/dev/null || true
  [[ -f "$AUTO_UPGRADES_FILE" ]] && cp "$AUTO_UPGRADES_FILE" "${d}/" 2>/dev/null || true

  state_set "hardening_last_backup" "$d"
  log_info "Backup создан: ${d}"
  hardening_trim_backups
}

hardening_trim_backups() {
  [[ -d "$HARDENING_BACKUP_ROOT" ]] || return 0
  local count
  count="$(find "$HARDENING_BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)"
  if (( count > HARDENING_BACKUP_KEEP )); then
    find "$HARDENING_BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' 2>/dev/null \
      | sort -n | head -n $((count - HARDENING_BACKUP_KEEP)) | awk '{print $2}' \
      | xargs -r rm -rf
  fi
}

# ---------------------------------------------------------------------------
# Packages
# ---------------------------------------------------------------------------

hardening_install_packages() {
  local need=() pkg
  for pkg in ufw fail2ban unattended-upgrades; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
      need+=("$pkg")
    fi
  done
  if (( ${#need[@]} == 0 )); then
    log_info "Пакеты на месте: ufw fail2ban unattended-upgrades"
    return 0
  fi
  log_info "Устанавливаю: ${need[*]}"
  DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${need[@]}" >/dev/null
}

# ---------------------------------------------------------------------------
# UFW
# ---------------------------------------------------------------------------

# Добавить одно allow-правило. source пустой / "Anywhere" → открыто миру.
_ufw_allow_port() {
  local port="$1" src="${2:-}" comment="${3:-audit-allow}"
  if [[ -z "$src" || "$src" == "Anywhere" ]]; then
    ufw allow "${port}/tcp" comment "$comment" >/dev/null
  else
    ufw allow from "$src" to any port "$port" proto tcp comment "$comment" >/dev/null
  fi
}

# Source-IP, с которым порт должен быть открыт.
# NODE_PORT_ALLOW_FROM ограничивает порт связи с панелью её IP — так же, как
# это делается в ручном hardening'е. Для остальных портов — пусто (Anywhere).
_ufw_desired_source() {
  local port="$1"
  if [[ -n "${NODE_PORT_ALLOW_FROM:-}" && -n "${NODE_PORT:-}" && "$port" == "${NODE_PORT}" ]]; then
    printf '%s' "$NODE_PORT_ALLOW_FROM"
  fi
}

# hardening_setup_ufw <ssh_port> <whitelist_csv> [rate_limit_flag] [mode]
#
# mode:
#   preserve (default) — НИЧЕГО не удаляет. Выставляет политику по умолчанию
#       и доносит только недостающие allow-правила. Порт, у которого уже есть
#       правило (с любым source), не трогается вовсе — поэтому ручные
#       ограничения вида `allow from <IP панели> to any port 2222` переживают
#       установку без изменений.
#   reset — полная пересборка (старое поведение). Source-IP существующих
#       правил снимается ДО reset и восстанавливается после, чтобы пересборка
#       не превращала port-restricted правило в открытое миру.
hardening_setup_ufw() {
  local ssh_port="$1" whitelist_csv="$2" rate_limit="${3:-0}"
  local mode="${4:-${HARDENING_UFW_MODE:-${UFW_MODE:-preserve}}}"

  if [[ -z "$ssh_port" || ! "$ssh_port" =~ ^[0-9]+$ ]]; then
    abort_expected "ufw setup: некорректный SSH порт '${ssh_port}'"
    return 1
  fi
  if [[ -z "$whitelist_csv" ]]; then
    abort_expected "ufw setup: пустой whitelist"
    return 1
  fi
  if [[ "$mode" != "preserve" && "$mode" != "reset" ]]; then
    abort_expected "ufw setup: неизвестный UFW_MODE='${mode}' (ожидается preserve|reset)"
    return 1
  fi

  # === SANITY: SSH порт обязан быть в whitelist ===
  if ! _csv_contains "$whitelist_csv" "$ssh_port"; then
    abort_expected "SSH порт ${ssh_port} НЕ в whitelist (${whitelist_csv}). UFW отрубит SSH-сессию. ABORT."
    return 1
  fi

  # Дополнительная страховка для активной SSH-сессии
  if [[ -n "${SSH_CONNECTION:-}" ]]; then
    local our_ip="${SSH_CONNECTION%% *}"
    log_info "Активная SSH-сессия: ${our_ip} → :${ssh_port}. SSH порт в allow — сессия не оборвётся."
  fi

  local ufw_active=0
  if ufw status 2>/dev/null | head -1 | grep -q 'Status: active'; then
    ufw_active=1
  fi

  # Фиксируем ОДИН раз, при первой настройке: был ли firewall поднят до нас.
  # Если был — rollback не имеет права его выключать (это не наш firewall).
  if [[ -z "$(state_get 'hardening_ufw_preexisting' '')" ]]; then
    state_set "hardening_ufw_preexisting" "$ufw_active"
  fi

  if [[ "$mode" == "preserve" ]]; then
    _ufw_apply_preserve "$ssh_port" "$whitelist_csv" "$rate_limit" "$ufw_active" || return 1
  else
    _ufw_apply_reset "$ssh_port" "$whitelist_csv" "$rate_limit" "$ufw_active" || return 1
  fi

  state_set "hardening_ufw_managed" "1"
  state_set "hardening_ufw_mode" "$mode"
  return 0
}

# --- preserve: только дополняем, ничего не удаляем -------------------------
_ufw_apply_preserve() {
  local ssh_port="$1" whitelist_csv="$2" rate_limit="$3" ufw_active="$4"

  if (( ufw_active == 1 )); then
    log_info "UFW: режим preserve — существующие правила сохраняются, добавляю только недостающие"
    local extras
    extras="$(ports_ufw_extras_csv "$whitelist_csv")"
    if [[ -n "$extras" ]]; then
      log_info "UFW: правила вне whitelist оставлены нетронутыми: ${extras}"
      log_info "     (чтобы мониторинг не считал их дрейфом — EXTRA_PORTS_WHITELIST=${extras})"
    fi
  else
    log_info "UFW: неактивен — настраиваю с нуля (allow ${whitelist_csv})"
  fi

  ufw default deny incoming  >/dev/null 2>&1
  ufw default allow outgoing >/dev/null 2>&1

  # SSH — первым, чтобы enable ниже не оборвал сессию.
  if ports_ufw_has_port "$ssh_port"; then
    log_info "UFW: SSH ${ssh_port} уже разрешён — правило не трогаю"
  elif [[ "$rate_limit" == "1" ]]; then
    ufw limit "${ssh_port}/tcp" comment 'audit-ssh-rl' >/dev/null
    log_info "UFW: + limit ${ssh_port}/tcp (SSH, rate-limit)"
  else
    ufw allow "${ssh_port}/tcp" comment 'audit-ssh' >/dev/null
    log_info "UFW: + allow ${ssh_port}/tcp (SSH)"
  fi

  local p src added=0 kept=0
  local IFS=','
  for p in $whitelist_csv; do
    [[ -z "$p" || "$p" == "$ssh_port" ]] && continue
    [[ "$p" =~ ^[0-9]+$ ]] || continue
    if ports_ufw_has_port "$p"; then
      kept=$((kept + 1))
      continue
    fi
    src="$(_ufw_desired_source "$p")"
    _ufw_allow_port "$p" "$src" 'audit-allow'
    if [[ -n "$src" ]]; then
      log_info "UFW: + allow from ${src} to any port ${p}/tcp"
    else
      log_info "UFW: + allow ${p}/tcp"
    fi
    added=$((added + 1))
  done
  unset IFS

  if (( ufw_active == 0 )); then
    ufw --force enable >/dev/null
  fi

  log_info "UFW активен (preserve). Добавлено правил: ${added}, оставлено без изменений: ${kept}"

  # Предупреждаем, если порт панели остался открытым миру, хотя мог бы быть
  # ограничен IP панели — это ровно та дыра, которую закрывает ручной hardening.
  if [[ -n "${NODE_PORT:-}" ]] && [[ -z "${NODE_PORT_ALLOW_FROM:-}" ]]; then
    local cur_src
    cur_src="$(ports_ufw_source_for "$NODE_PORT")"
    if [[ -z "$cur_src" ]]; then
      log_warn "NODE_PORT ${NODE_PORT} открыт всему интернету. Безопаснее ограничить IP панели:"
      log_warn "  NODE_PORT_ALLOW_FROM=<IP панели> в ${CONFIG_PATH:-/etc/remnawave-audit/audit.conf}"
    else
      log_info "NODE_PORT ${NODE_PORT} ограничен source ${cur_src} — сохранено"
    fi
  fi
  return 0
}

# --- reset: полная пересборка, с переносом source-IP -----------------------
_ufw_apply_reset() {
  local ssh_port="$1" whitelist_csv="$2" rate_limit="$3" ufw_active="$4"

  # Снимаем карту port→source ДО reset: иначе port-restricted правила
  # пересоздадутся как открытые миру.
  declare -A saved_src=()
  local port from
  while IFS='|' read -r port _ from _; do
    [[ -z "$port" ]] && continue
    [[ "$from" == "Anywhere" || -z "$from" ]] && continue
    [[ -n "${saved_src[$port]:-}" ]] && continue
    saved_src["$port"]="$from"
  done < <(ports_ufw_rules)

  if (( ufw_active == 1 )); then
    local extras
    extras="$(ports_ufw_extras_csv "$whitelist_csv")"

    if [[ -z "$extras" ]]; then
      log_info "UFW active, все правила ∈ whitelist — reset идемпотентен"
    elif [[ "${HARDENING_UFW_FORCE_RESET:-0}" != "1" ]]; then
      log_error "UFW активен с правилами вне нашего whitelist: ${extras}"
      ufw status 2>/dev/null | head -20 >&2
      log_error "Режим reset снесёт эти правила."
      log_error "Варианты:"
      log_error "  1. UFW_MODE=preserve (по умолчанию) — дополнить, ничего не удаляя;"
      log_error "  2. EXTRA_PORTS_WHITELIST=${extras} в конфиге — пересоздать их вместе с остальными;"
      log_error "  3. --ufw-force-reset / HARDENING_UFW_FORCE_RESET=1 — снести осознанно."
      log_error "Snapshot правил уже в backup'е."
      abort_expected ""
      return 1
    else
      log_warn "HARDENING_UFW_FORCE_RESET=1 — сношу правила ${extras} (вне whitelist)"
    fi
  fi

  log_info "UFW: reset → default deny → allow ${whitelist_csv} → enable"

  ufw --force reset >/dev/null 2>&1
  ufw default deny incoming  >/dev/null 2>&1
  ufw default allow outgoing >/dev/null 2>&1

  # SSH правило — первым; опционально с rate-limit. SSH никогда не ограничиваем
  # по source автоматически: ошибка тут стоит потери доступа к серверу.
  if [[ "$rate_limit" == "1" ]]; then
    ufw limit "${ssh_port}/tcp" comment 'audit-ssh-rl' >/dev/null
  else
    ufw allow "${ssh_port}/tcp" comment 'audit-ssh' >/dev/null
  fi

  local p src
  local IFS=','
  for p in $whitelist_csv; do
    [[ -z "$p" || "$p" == "$ssh_port" ]] && continue
    [[ "$p" =~ ^[0-9]+$ ]] || continue
    # Явная настройка важнее того, что было; иначе восстанавливаем прежний source.
    src="$(_ufw_desired_source "$p")"
    [[ -z "$src" ]] && src="${saved_src[$p]:-}"
    _ufw_allow_port "$p" "$src" 'audit-allow'
    [[ -n "$src" ]] && log_info "UFW: ${p}/tcp ограничен source ${src} (сохранено при пересборке)"
  done
  unset IFS

  ufw --force enable >/dev/null
  log_info "UFW активен (reset). Allow: ${whitelist_csv}"
  return 0
}

# ---------------------------------------------------------------------------
# fail2ban
# ---------------------------------------------------------------------------

# Путь к ЧУЖОМУ конфигу, объявляющему [sshd] jail (не нашему). Пусто — нет такого.
#
# Важно: fail2ban склеивает jail.local и jail.d/* в алфавитном порядке, и
# последний прочитанный файл переопределяет предыдущие. Наш
# `remnawave-audit.local` идёт раньше типичного `sshd.local`, поэтому чужой
# конфиг молча выигрывает. Тихо писать свой файл поверх — значит создать
# иллюзию управления настройками, которые на деле не применяются.
_fail2ban_foreign_sshd_jail() {
  local f
  for f in "${FAIL2BAN_DIR}/jail.local" "${FAIL2BAN_DIR}"/jail.d/*.conf "${FAIL2BAN_DIR}"/jail.d/*.local; do
    [[ -f "$f" ]] || continue
    [[ "$f" == "$FAIL2BAN_JAIL_FILE" ]] && continue
    if grep -qE '^\[sshd\]' "$f" 2>/dev/null; then
      printf '%s' "$f"
      return 0
    fi
  done
  return 0
}

# hardening_setup_fail2ban <ssh_port> [admin_ips_csv] [mode]
#
# mode:
#   preserve (default) — если [sshd] jail уже настроен админом, свой конфиг
#       не пишем: проверяем, что сервис включён, и оставляем как есть.
#   manage — всегда писать свой jail (перетирает наш прежний файл; чужой
#       файл при этом всё равно может выиграть по приоритету — предупредим).
hardening_setup_fail2ban() {
  local ssh_port="$1" admin_ips_csv="${2:-}"
  local mode="${3:-${HARDENING_FAIL2BAN_MODE:-${FAIL2BAN_MODE:-preserve}}}"
  if [[ -z "$ssh_port" || ! "$ssh_port" =~ ^[0-9]+$ ]]; then
    log_error "fail2ban setup: некорректный SSH порт '${ssh_port}'"
    return 1
  fi

  local foreign
  foreign="$(_fail2ban_foreign_sshd_jail)"

  if [[ -n "$foreign" ]]; then
    if [[ "$mode" == "preserve" ]]; then
      log_info "fail2ban: [sshd] jail уже настроен в ${foreign} — оставляю как есть (FAIL2BAN_MODE=preserve)"
      # Наш jail мог остаться от установки в режиме manage. Не удаляем его молча
      # (это чужое решение админа), но и не даём забыть о двух источниках правды.
      if [[ -f "$FAIL2BAN_JAIL_FILE" ]]; then
        log_warn "fail2ban: от прошлой установки остался ${FAIL2BAN_JAIL_FILE}"
        log_warn "  Действуют оба файла; при конфликте ключей выигрывает ${foreign}."
        log_warn "  Убрать наш: rm ${FAIL2BAN_JAIL_FILE} && systemctl reload fail2ban"
      fi
      systemctl enable fail2ban >/dev/null 2>&1 || true
      systemctl is-active --quiet fail2ban || systemctl start fail2ban >/dev/null 2>&1 || true
      if systemctl is-active --quiet fail2ban; then
        log_info "fail2ban: сервис активен, чужой jail не тронут"
      else
        log_warn "fail2ban: сервис не запустился — проверь ${foreign} (fail2ban-client status sshd)"
      fi
      state_set "hardening_fail2ban_managed" "0"
      return 0
    fi
    log_warn "fail2ban: [sshd] jail также объявлен в ${foreign}."
    log_warn "  fail2ban читает jail.d по алфавиту — при конфликте выигрывает файл с именем позже."
    log_warn "  Наш файл: ${FAIL2BAN_JAIL_FILE}. Сверь итог: fail2ban-client get sshd maxretry"
  fi

  local ignoreip="127.0.0.1/8 ::1"
  if [[ -n "$admin_ips_csv" ]]; then
    ignoreip+=" $(printf '%s' "$admin_ips_csv" | tr ',' ' ')"
  fi

  # На минимальных Ubuntu /var/log/auth.log отсутствует (только journald).
  # fail2ban падает с "Have not found any log file for sshd jail" если backend=auto.
  local backend="auto"
  if [[ ! -f /var/log/auth.log ]]; then
    backend="systemd"
    log_info "fail2ban: /var/log/auth.log отсутствует — используем backend=systemd"
  fi

  mkdir -p /etc/fail2ban/jail.d

  local tmp
  tmp="$(mktemp /etc/fail2ban/jail.d/.audit.XXXXXX)"
  cat > "$tmp" <<EOF
# Managed by remnawave-node-audit. Не редактируй вручную.
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
ignoreip = ${ignoreip}

[sshd]
enabled  = true
port     = ${ssh_port}
backend  = ${backend}
EOF
  chmod 644 "$tmp"
  mv "$tmp" "$FAIL2BAN_JAIL_FILE"

  systemctl enable fail2ban >/dev/null 2>&1 || true
  if systemctl is-active --quiet fail2ban; then
    systemctl reload fail2ban >/dev/null 2>&1 || systemctl restart fail2ban >/dev/null 2>&1
  else
    systemctl start fail2ban >/dev/null 2>&1
  fi
  state_set "hardening_fail2ban_managed" "1"
  log_info "fail2ban: jail [sshd] (port=${ssh_port}, backend=${backend}, ignoreip=${ignoreip})"
}

# ---------------------------------------------------------------------------
# unattended-upgrades
# ---------------------------------------------------------------------------

hardening_setup_unattended_upgrades() {
  if ! dpkg -s unattended-upgrades >/dev/null 2>&1; then
    log_warn "unattended-upgrades не установлен — пропускаю (apt install -y unattended-upgrades)"
    return 0
  fi

  local tmp
  tmp="$(mktemp "${UNATTENDED_FILE}.tmp.XXXXXX")"
  cat > "$tmp" <<'EOF'
// Managed by remnawave-node-audit. Только security-патчи, без auto-reboot.
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::DevRelease "auto";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Dependencies "false";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
EOF
  chmod 644 "$tmp"
  mv "$tmp" "$UNATTENDED_FILE"

  tmp="$(mktemp "${AUTO_UPGRADES_FILE}.tmp.XXXXXX")"
  cat > "$tmp" <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
EOF
  chmod 644 "$tmp"
  mv "$tmp" "$AUTO_UPGRADES_FILE"

  # apt-listchanges может блокировать неинтерактивно — отключим если есть.
  if dpkg -s apt-listchanges >/dev/null 2>&1 && [[ -f /etc/apt/listchanges.conf ]]; then
    sed -i 's/^frontend=.*/frontend=none/' /etc/apt/listchanges.conf 2>/dev/null || true
  fi

  systemctl enable unattended-upgrades >/dev/null 2>&1 || true
  systemctl restart unattended-upgrades >/dev/null 2>&1 || true

  state_set "hardening_unattended_managed" "1"
  log_info "unattended-upgrades: только -security, Automatic-Reboot=false"
}

# ---------------------------------------------------------------------------
# NTP (критично для ноды Remnawave: без синхронизации часов TLS/JWT
# с панелью ломаются. См. INSTRUCTION.md §3.4.)
# ---------------------------------------------------------------------------

_ntp_wait_synced() {
  local timeout="${1:-30}" i=0
  while (( i < timeout )); do
    sleep 5
    i=$((i + 5))
    if timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -q '^yes$'; then
      return 0
    fi
  done
  return 1
}

# hardening_setup_ntp
# Best-effort: пробует стандартный NTP, при провале — chrony + NTS
# (Cloudflare/Netnod поверх TCP/443, обходит блокировку UDP/123 на VPS).
# Не падает при провале — это не блокирует установку, просто алерт.
hardening_setup_ntp() {
  log_info "NTP: timedatectl set-ntp true"
  timedatectl set-ntp true 2>/dev/null || true

  if systemctl list-unit-files systemd-timesyncd.service 2>/dev/null | grep -q timesyncd; then
    systemctl restart systemd-timesyncd 2>/dev/null || true
  fi
  if systemctl is-active --quiet chrony 2>/dev/null; then
    systemctl restart chrony 2>/dev/null || true
  fi

  if _ntp_wait_synced 30; then
    log_info "NTP: синхронизировано стандартным NTP"
    state_set "hardening_ntp_managed" "standard"
    return 0
  fi

  log_warn "NTP: стандартный (UDP/123) не синкнулся за 30с — переключаюсь на NTS поверх TCP/443"

  if ! dpkg -s chrony >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq chrony >/dev/null
  fi
  systemctl disable --now systemd-timesyncd 2>/dev/null || true
  mkdir -p /etc/chrony/conf.d
  cat > /etc/chrony/conf.d/nts.conf <<'EOF'
# Managed by remnawave-node-audit. NTS поверх TCP/443 — обходит
# блокировку UDP/123 на VPS-провайдерах. Не редактируй вручную.
server time.cloudflare.com iburst nts
server nts.netnod.se iburst nts
EOF
  systemctl enable chrony >/dev/null 2>&1 || true
  systemctl restart chrony

  if _ntp_wait_synced 60; then
    log_info "NTP: синхронизировано через chrony+NTS"
    state_set "hardening_ntp_managed" "nts"
    return 0
  fi

  log_warn "NTP: NTS-серверы тоже недоступны (провайдер блокирует и TCP/443 к ним)"
  log_info "NTP: переключаюсь на htpdate — синхронизация через HTTP Date headers обычных сайтов"
  _ntp_setup_htpdate_fallback
}

# htpdate — последний fallback. Использует обычные HTTPS-сайты (google/github/
# telegram), которые работают практически всегда (иначе VPS бесполезен).
# Точность ±1 секунда — этого хватает для mTLS/JWT (там допуск минут).
# Запускает синхронизацию раз в час через systemd таймер.
_ntp_setup_htpdate_fallback() {
  if ! dpkg -s htpdate >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq htpdate >/dev/null
  fi

  # chrony больше не нужен — отключаем чтобы не флапал в логах
  systemctl disable --now chrony 2>/dev/null || true
  systemctl disable --now systemd-timesyncd 2>/dev/null || true

  # Однократная синхронизация прямо сейчас (множественные источники = quorum)
  htpdate -s -t \
    https://www.google.com \
    https://github.com \
    https://api.telegram.org \
    2>/dev/null || log_warn "htpdate: первичная синхронизация не сработала"

  # Systemd timer для регулярной синхронизации
  cat > /etc/systemd/system/htpdate-sync.service <<'EOF'
[Unit]
Description=Time sync via HTTPS Date headers (htpdate fallback)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/htpdate -s -t https://www.google.com https://github.com https://api.telegram.org
TimeoutStartSec=30
EOF

  cat > /etc/systemd/system/htpdate-sync.timer <<'EOF'
[Unit]
Description=Run htpdate every hour for time sync

[Timer]
OnBootSec=2min
OnUnitActiveSec=1h
RandomizedDelaySec=5min

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable --now htpdate-sync.timer >/dev/null 2>&1

  # Проверяем что время хотя бы похоже на правильное (в пределах последнего года).
  local now_unix expected_min
  now_unix="$(date +%s)"
  expected_min=1735689600  # 2025-01-01
  if (( now_unix > expected_min )); then
    log_info "NTP: время синхронизировано через htpdate (HTTPS), таймер каждый час"
    state_set "hardening_ntp_managed" "htpdate"
  else
    log_warn "NTP: htpdate не помог. Возможно весь outbound HTTPS блокирован."
    state_set "hardening_ntp_managed" "failed"
  fi
  return 0  # best-effort, не блокируем установку
}

# ---------------------------------------------------------------------------
# Главная функция
# ---------------------------------------------------------------------------

# hardening_run [--skip-ufw] [--skip-fail2ban] [--skip-unattended]
#               [--skip-ntp] [--ufw-rate-limit]
hardening_run() {
  is_root || { log_error "hardening требует root"; return 1; }

  local skip_ufw=0 skip_f2b=0 skip_unat=0 skip_ntp=0 ufw_rl=0
  local ufw_mode="${HARDENING_UFW_MODE:-${UFW_MODE:-preserve}}"
  local f2b_mode="${HARDENING_FAIL2BAN_MODE:-${FAIL2BAN_MODE:-preserve}}"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --skip-ufw)        skip_ufw=1 ;;
      --skip-fail2ban)   skip_f2b=1 ;;
      --skip-unattended) skip_unat=1 ;;
      --skip-ntp)        skip_ntp=1 ;;
      --ufw-rate-limit)  ufw_rl=1 ;;
      --ufw-mode=*)      ufw_mode="${1#*=}" ;;
      --fail2ban-mode=*) f2b_mode="${1#*=}" ;;
    esac
    shift
  done

  printf '\n=== Hardening: UFW + fail2ban + auto-upgrades + NTP ===\n'

  hardening_backup
  hardening_install_packages

  if (( skip_ufw == 0 )); then
    local ssh_port whitelist
    ssh_port="$(ports_sshd_port)"
    whitelist="$(ports_full_whitelist_csv)"
    hardening_setup_ufw "$ssh_port" "$whitelist" "$ufw_rl" "$ufw_mode" || return 1
  else
    log_info "UFW: пропуск (--skip-ufw)"
  fi

  if (( skip_f2b == 0 )); then
    hardening_setup_fail2ban "$(ports_sshd_port)" "${SSH_ADMIN_IPS:-}" "$f2b_mode"
  else
    log_info "fail2ban: пропуск (--skip-fail2ban)"
  fi

  if (( skip_unat == 0 )); then
    hardening_setup_unattended_upgrades
  else
    log_info "unattended-upgrades: пропуск (--skip-unattended)"
  fi

  if (( skip_ntp == 0 )); then
    hardening_setup_ntp
  else
    log_info "NTP: пропуск (--skip-ntp)"
  fi

  state_set "hardening_done" "1"
  state_set "hardening_done_at" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  printf '\n=== Hardening завершён ===\n'
}

# ---------------------------------------------------------------------------
# Rollback (soft)
# ---------------------------------------------------------------------------

# hardening_rollback [--yes]
# Soft: ufw disable + удалить наш fail2ban jail. unattended-upgrades конфиги
# не откатываем (они безопасные). Полное состояние — в backup'ах.
hardening_rollback() {
  is_root || { log_error "rollback требует root"; return 1; }

  local force=0
  [[ "${1:-}" == "--yes" ]] && force=1

  # UFW, поднятый админом до установки, откатом не выключаем — мы его не
  # включали. Иначе «откат нашего скрипта» снимает чужую защиту с сервера.
  local ufw_preexisting
  ufw_preexisting="$(state_get 'hardening_ufw_preexisting' '0')"

  printf '\n=== Hardening rollback (soft) ===\n'
  if [[ "$ufw_preexisting" == "1" ]]; then
    printf 'UFW был активен ДО установки — остаётся включённым (не наш firewall).\n'
  else
    printf 'Будет: ufw disable.\n'
  fi
  printf 'Будет: удалить %s, перезапустить fail2ban.\n' "$FAIL2BAN_JAIL_FILE"
  printf 'unattended-upgrades НЕ откатывается (безопасный конфиг).\n'
  printf 'Полные snapshot-ы: %s\n\n' "$HARDENING_BACKUP_ROOT"

  if (( force == 0 )); then
    printf 'Продолжить? [y/N]: '
    local reply; read -r reply
    [[ "$reply" != "y" && "$reply" != "Y" ]] && { log_info "Отменено."; return 0; }
  fi

  if command -v ufw >/dev/null 2>&1; then
    if [[ "$ufw_preexisting" == "1" ]]; then
      log_info "ufw оставлен включённым (был активен до установки)"
      log_info "Наши правила помечены комментарием audit-allow / audit-ssh — удали вручную при необходимости:"
      log_info "  ufw status numbered | grep audit-"
    else
      ufw --force disable >/dev/null 2>&1 || true
      log_info "ufw disabled"
    fi
  fi

  if [[ -f "$FAIL2BAN_JAIL_FILE" ]]; then
    rm -f "$FAIL2BAN_JAIL_FILE"
    systemctl reload fail2ban >/dev/null 2>&1 || systemctl restart fail2ban >/dev/null 2>&1 || true
    log_info "fail2ban jail удалён"
  fi

  state_unset "hardening_ufw_managed"
  state_unset "hardening_fail2ban_managed"
  state_unset "hardening_done"

  printf '\n=== Rollback завершён ===\n'
}
