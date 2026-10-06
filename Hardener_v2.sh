#!/usr/bin/env bash
# ============================================================
# CyberPatriot Linux Mint / Ubuntu Interactive Hardening Tool
# Version 2.0
#
# Designed for CyberPatriot-style Ubuntu / Linux Mint images.
#
# IMPORTANT:
#   1. READ THE README AND FORENSICS QUESTIONS FIRST.
#   2. This script is intentionally interactive.
#   3. Do not modify CyberPatriot scoring components.
#   4. Required users/services/files differ between images.
#
# Run:
#   sudo bash CyberPatriot_Mint_Hardener_v2.sh
#
# Audit-only:
#   sudo bash CyberPatriot_Mint_Hardener_v2.sh --audit
# ============================================================

set -uo pipefail
IFS=$'\n\t'

AUDIT_ONLY=0
[[ "${1:-}" == "--audit" ]] && AUDIT_ONLY=1

TS="$(date +%Y%m%d_%H%M%S)"
WORKDIR="/root/cp-hardener-$TS"
BACKUP_DIR="$WORKDIR/backups"
LOG="$WORKDIR/hardener.log"
REPORT="$WORKDIR/report.txt"

mkdir -p "$BACKUP_DIR"
touch "$LOG" "$REPORT"
chmod 700 "$WORKDIR" "$BACKUP_DIR"
chmod 600 "$LOG" "$REPORT"

if [[ -t 1 ]]; then
  BOLD=$'\033[1m'
  RED=$'\033[31m'
  GREEN=$'\033[32m'
  YELLOW=$'\033[33m'
  BLUE=$'\033[34m'
  CYAN=$'\033[36m'
  RESET=$'\033[0m'
else
  BOLD=""; RED=""; GREEN=""; YELLOW=""; BLUE=""; CYAN=""; RESET=""
fi

log(){ printf '%s\n' "$*" | tee -a "$LOG"; }
report(){ printf '%s\n' "$*" >> "$REPORT"; }

section(){
  printf '\n%s== %s ==%s\n' "$BOLD$BLUE" "$*" "$RESET"
  printf '\n== %s ==\n' "$*" >> "$LOG"
  printf '\n== %s ==\n' "$*" >> "$REPORT"
}

warn(){ printf '%sWARNING:%s %s\n' "$YELLOW" "$RESET" "$*" | tee -a "$LOG"; }
ok(){ printf '%sOK:%s %s\n' "$GREEN" "$RESET" "$*" | tee -a "$LOG"; }
info(){ printf '%sINFO:%s %s\n' "$CYAN" "$RESET" "$*" | tee -a "$LOG"; }
err(){ printf '%sERROR:%s %s\n' "$RED" "$RESET" "$*" | tee -a "$LOG" >&2; }

ask_yes_no(){
  local prompt="$1" default="${2:-N}" ans
  [[ $AUDIT_ONLY -eq 1 ]] && return 1

  if [[ "$default" == "Y" ]]; then
    read -r -p "$prompt [Y/n]: " ans
    ans="${ans:-Y}"
  else
    read -r -p "$prompt [y/N]: " ans
    ans="${ans:-N}"
  fi

  [[ "$ans" =~ ^[Yy]$ ]]
}

run(){
  log "+ $*"
  "$@" 2>&1 | tee -a "$LOG"
  return "${PIPESTATUS[0]}"
}

backup_file(){
  local f="$1"
  if [[ -e "$f" ]]; then
    local dest="$BACKUP_DIR${f}"
    mkdir -p "$(dirname "$dest")"
    cp -a "$f" "$dest"
    log "Backed up $f -> $dest"
  fi
}

parse_list(){
  local raw="$1"
  printf '%s\n' "$raw" | tr ', ' '\n\n' | sed '/^[[:space:]]*$/d' | sort -u
}

contains_line(){
  local needle="$1" haystack="$2"
  grep -Fxq -- "$needle" <<< "$haystack"
}

is_login_shell(){
  local shell="$1"
  [[ "$shell" != */nologin && "$shell" != */false && -n "$shell" ]]
}

is_required_service(){
  local svc="$1"
  local base="${svc%.service}"
  base="${base%.socket}"
  contains_line "$svc" "$REQUIRED_SERVICES" || contains_line "$base" "$REQUIRED_SERVICES"
}

if [[ $EUID -ne 0 ]]; then
  err "Run as root: sudo bash $0"
  exit 1
fi

if ! command -v apt >/dev/null 2>&1; then
  err "This tool targets Debian/Ubuntu/Linux Mint systems using apt."
  exit 1
fi

echo
echo "${BOLD}CyberPatriot Linux Mint / Ubuntu Hardening Tool v2.0${RESET}"
echo "Work directory: $WORKDIR"
warn "READ FORENSICS QUESTIONS BEFORE CHANGING THE IMAGE."
warn "READ THE README BEFORE CHANGING USERS, GROUPS, SERVICES, OR FILES."
warn "Never modify /opt/CyberPatriot or scoring-related files."
[[ $AUDIT_ONLY -eq 1 ]] && warn "AUDIT MODE ENABLED: changes will not be offered."

# ============================================================
# 1. SYSTEM INFO
# ============================================================
section "1. System Information"

if [[ -r /etc/os-release ]]; then
  . /etc/os-release
  DISTRO="${PRETTY_NAME:-unknown}"
else
  DISTRO="unknown"
fi

log "Distribution: $DISTRO"
log "Hostname: $(hostname)"
log "Kernel: $(uname -r)"
log "Date: $(date -Is)"

# ============================================================
# 2. SCENARIO INPUT
# ============================================================
section "2. Scenario Inputs From README"

echo "Separate multiple values with spaces or commas."
echo

read -r -p "Authorized STANDARD users: " AUTH_USERS_RAW
read -r -p "Authorized ADMINISTRATORS: " AUTH_ADMINS_RAW
read -r -p "Required services (example: ssh vsftpd apache2): " REQUIRED_SERVICES_RAW
read -r -p "Required incoming ports (example: 22/tcp 21/tcp): " REQUIRED_PORTS_RAW

AUTH_USERS="$(parse_list "$AUTH_USERS_RAW")"
AUTH_ADMINS="$(parse_list "$AUTH_ADMINS_RAW")"
REQUIRED_SERVICES="$(parse_list "$REQUIRED_SERVICES_RAW")"
REQUIRED_PORTS="$(parse_list "$REQUIRED_PORTS_RAW")"
ALL_AUTHORIZED="$(printf '%s\n%s\n' "$AUTH_USERS" "$AUTH_ADMINS" | sed '/^$/d' | sort -u)"

echo
echo "README group requirements"
echo "Example: spider:nova,rowan,finn,quinn"
echo "Enter one group at a time. Press Enter for group name when done."
declare -a GROUP_NAMES=()
declare -a GROUP_MEMBERS=()

if [[ $AUDIT_ONLY -eq 0 ]]; then
  while true; do
    read -r -p "Required group name (blank = done): " grp
    [[ -z "$grp" ]] && break
    read -r -p "Members for '$grp' (comma/space separated): " members
    GROUP_NAMES+=("$grp")
    GROUP_MEMBERS+=("$members")
  done
fi

read -r -p "Prohibited package names from README, if any (blank if none): " PROHIBITED_PKGS_RAW
PROHIBITED_PKGS="$(parse_list "$PROHIBITED_PKGS_RAW")"

read -r -p "Prohibited file extensions from README (example: ogg mp3 mp4 zip), blank if none: " PROHIBITED_EXTS_RAW
PROHIBITED_EXTS="$(parse_list "$PROHIBITED_EXTS_RAW")"

PASS_MAX_DAYS=90
PASS_MIN_DAYS=1
PASS_WARN_AGE=7
PW_MINLEN=12

if [[ $AUDIT_ONLY -eq 0 ]]; then
  read -r -p "Password maximum age [$PASS_MAX_DAYS]: " tmp
  PASS_MAX_DAYS="${tmp:-$PASS_MAX_DAYS}"

  read -r -p "Password minimum age [$PASS_MIN_DAYS]: " tmp
  PASS_MIN_DAYS="${tmp:-$PASS_MIN_DAYS}"

  read -r -p "Password warning days [$PASS_WARN_AGE]: " tmp
  PASS_WARN_AGE="${tmp:-$PASS_WARN_AGE}"

  read -r -p "Minimum password length [$PW_MINLEN]: " tmp
  PW_MINLEN="${tmp:-$PW_MINLEN}"
fi

# ============================================================
# 3. BASELINE
# ============================================================
section "3. Baseline Snapshot"

{
  echo "Date: $(date -Is)"
  echo
  echo "--- /etc/passwd ---"
  cat /etc/passwd
  echo
  echo "--- /etc/group ---"
  cat /etc/group
  echo
  echo "--- sudo ---"
  getent group sudo || true
  echo
  echo "--- listening sockets ---"
  ss -tulpn 2>/dev/null || true
  echo
  echo "--- running services ---"
  systemctl list-units --type=service --state=active --no-pager 2>/dev/null || true
  echo
  echo "--- enabled services ---"
  systemctl list-unit-files --type=service --state=enabled --no-pager 2>/dev/null || true
  echo
  echo "--- ufw ---"
  ufw status verbose 2>/dev/null || true
} > "$WORKDIR/baseline.txt"

ok "Baseline saved to $WORKDIR/baseline.txt"

# ============================================================
# 4. USERS INCLUDING HIDDEN LOW-UID USERS
# ============================================================
section "4. Users and Administrators"

echo "All accounts with UID, home, and shell:"
awk -F: '{printf "%-20s uid=%-6s home=%-30s shell=%s\n",$1,$3,$6,$7}' /etc/passwd | tee -a "$REPORT"

echo
info "Checking normal users AND suspicious login-capable low-UID accounts."

SUSPECT_USER_LIST="$(
  awk -F: '
  {
    user=$1; uid=$3; home=$6; shell=$7;
    login=(shell !~ /(nologin|false)$/);
    homedir=(home ~ /^\/home\//);
    if ((uid >= 1000 && user != "nobody") || (login && homedir))
      print user
  }' /etc/passwd | sort -u
)"

echo "User-like/login-capable accounts:"
printf '  %s\n' $SUSPECT_USER_LIST 2>/dev/null || true

if [[ -n "$ALL_AUTHORIZED" ]]; then
  for u in $SUSPECT_USER_LIST; do
    [[ -z "$u" ]] && continue

    if ! contains_line "$u" "$ALL_AUTHORIZED"; then
      uid="$(id -u "$u" 2>/dev/null || echo '?')"
      home="$(getent passwd "$u" | cut -d: -f6)"
      shell="$(getent passwd "$u" | cut -d: -f7)"

      warn "Potential unauthorized user: $u (uid=$uid home=$home shell=$shell)"

      if ask_yes_no "Delete unauthorized user '$u' and its home?"; then
        run deluser --remove-home "$u" || run userdel -r "$u" || warn "Could not fully remove $u."
      elif ask_yes_no "Lock '$u' instead?"; then
        run usermod -L "$u"
      fi
    fi
  done
fi

echo
echo "Current sudo members:"
getent group sudo || true

for u in $AUTH_ADMINS; do
  [[ -z "$u" ]] && continue

  if ! id "$u" >/dev/null 2>&1; then
    warn "Authorized administrator '$u' does not exist."
    ask_yes_no "Create '$u'?" && adduser "$u"
  fi

  if id "$u" >/dev/null 2>&1 && ! id -nG "$u" | tr ' ' '\n' | grep -Fxq sudo; then
    warn "$u should be an administrator but is not in sudo."
    ask_yes_no "Add '$u' to sudo?" && run usermod -aG sudo "$u"
  fi
done

for u in $AUTH_USERS; do
  [[ -z "$u" ]] && continue

  if ! id "$u" >/dev/null 2>&1; then
    warn "Authorized standard user '$u' does not exist."
    ask_yes_no "Create '$u'?" && adduser "$u"
  fi

  if id "$u" >/dev/null 2>&1 && id -nG "$u" | tr ' ' '\n' | grep -Fxq sudo; then
    warn "$u is a STANDARD user but has sudo privileges."
    ask_yes_no "Remove '$u' from sudo?" && run gpasswd -d "$u" sudo
  fi
done

echo
echo "Other powerful groups:"
for g in sudo adm root docker lxd libvirt disk shadow; do
  getent group "$g" 2>/dev/null || true
done

# UID 0 accounts
UID0_USERS="$(awk -F: '$3 == 0 {print $1}' /etc/passwd)"
echo
echo "UID 0 accounts: $UID0_USERS"

for u in $UID0_USERS; do
  if [[ "$u" != "root" ]]; then
    warn "NON-ROOT UID 0 ACCOUNT: $u"
    ask_yes_no "Lock suspicious UID 0 account '$u'?" && run usermod -L "$u"
  fi
done

# ============================================================
# 5. REQUIRED GROUPS
# ============================================================
section "5. README-Required Groups"

if [[ ${#GROUP_NAMES[@]} -eq 0 ]]; then
  echo "No required groups entered."
else
  for i in "${!GROUP_NAMES[@]}"; do
    grp="${GROUP_NAMES[$i]}"
    members_raw="${GROUP_MEMBERS[$i]}"
    members_csv="$(printf '%s' "$members_raw" | tr ' ' ',' | sed 's/,,*/,/g; s/^,//; s/,$//')"

    if ! getent group "$grp" >/dev/null 2>&1; then
      warn "Required group '$grp' does not exist."
      ask_yes_no "Create group '$grp'?" && run addgroup "$grp"
    else
      ok "Group '$grp' exists."
    fi

    echo "Current:"
    getent group "$grp" || true

    if getent group "$grp" >/dev/null 2>&1 && [[ -n "$members_csv" ]]; then
      info "Required members: $members_csv"

      if ask_yes_no "Set '$grp' members to exactly: $members_csv ?"; then
        run gpasswd -M "$members_csv" "$grp"
      fi
    fi
  done
fi

# ============================================================
# 6. ROOT PASSWORD + EMPTY PASSWORDS
# ============================================================
section "6. Root and Empty Passwords"

ROOT_HASH="$(getent shadow root 2>/dev/null | cut -d: -f2 || true)"

if [[ -z "$ROOT_HASH" ]]; then
  warn "ROOT PASSWORD IS BLANK."
  if ask_yes_no "Lock the root password now?"; then
    run passwd -l root
  fi
elif [[ "$ROOT_HASH" == "!"* || "$ROOT_HASH" == "*"* ]]; then
  ok "Root password is already locked."
else
  info "Root has a password hash. Depending on the scenario, locking root may be appropriate."
fi

EMPTY_PASS_USERS="$(awk -F: '$2 == "" {print $1}' /etc/shadow 2>/dev/null || true)"

if [[ -n "$EMPTY_PASS_USERS" ]]; then
  warn "Accounts with blank password hashes:"
  printf '  %s\n' $EMPTY_PASS_USERS

  for u in $EMPTY_PASS_USERS; do
    if [[ "$u" == root ]]; then
      continue
    fi
    if ask_yes_no "Lock blank-password account '$u'?"; then
      run passwd -l "$u"
    fi
  done
else
  ok "No blank password hashes detected."
fi

# ============================================================
# 7. PASSWORD AGING
# ============================================================
section "7. Password Aging"

grep -E '^[[:space:]]*PASS_(MAX|MIN|WARN)_DAYS' /etc/login.defs 2>/dev/null || true

if ask_yes_no "Set login.defs to MAX=$PASS_MAX_DAYS MIN=$PASS_MIN_DAYS WARN=$PASS_WARN_AGE?"; then
  backup_file /etc/login.defs

  if grep -qE '^[#[:space:]]*PASS_MAX_DAYS' /etc/login.defs; then
    sed -ri "s/^[#[:space:]]*PASS_MAX_DAYS[[:space:]]+.*/PASS_MAX_DAYS   $PASS_MAX_DAYS/" /etc/login.defs
  else
    echo "PASS_MAX_DAYS   $PASS_MAX_DAYS" >> /etc/login.defs
  fi

  if grep -qE '^[#[:space:]]*PASS_MIN_DAYS' /etc/login.defs; then
    sed -ri "s/^[#[:space:]]*PASS_MIN_DAYS[[:space:]]+.*/PASS_MIN_DAYS   $PASS_MIN_DAYS/" /etc/login.defs
  else
    echo "PASS_MIN_DAYS   $PASS_MIN_DAYS" >> /etc/login.defs
  fi

  if grep -qE '^[#[:space:]]*PASS_WARN_AGE' /etc/login.defs; then
    sed -ri "s/^[#[:space:]]*PASS_WARN_AGE[[:space:]]+.*/PASS_WARN_AGE   $PASS_WARN_AGE/" /etc/login.defs
  else
    echo "PASS_WARN_AGE   $PASS_WARN_AGE" >> /etc/login.defs
  fi
fi

for u in $ALL_AUTHORIZED; do
  [[ -z "$u" ]] && continue
  id "$u" >/dev/null 2>&1 || continue

  echo
  chage -l "$u" 2>/dev/null || true

  if ask_yes_no "Apply password aging to '$u'?"; then
    run chage -M "$PASS_MAX_DAYS" -m "$PASS_MIN_DAYS" -W "$PASS_WARN_AGE" "$u"
  fi
done

# ============================================================
# 8. PAM MINIMUM LENGTH
# ============================================================
section "8. PAM Minimum Password Length"

COMMON_PASSWORD="/etc/pam.d/common-password"

if [[ -f "$COMMON_PASSWORD" ]]; then
  echo "pam_unix password line:"
  grep -nE '^[[:space:]]*password.*pam_unix\.so' "$COMMON_PASSWORD" || true

  if grep -E '^[[:space:]]*password.*pam_unix\.so' "$COMMON_PASSWORD" | grep -qE '(^|[[:space:]])minlen='; then
    CURRENT_MINLEN="$(grep -E '^[[:space:]]*password.*pam_unix\.so' "$COMMON_PASSWORD" | grep -oE 'minlen=[0-9]+' | head -1 || true)"
    ok "pam_unix already contains ${CURRENT_MINLEN:-a minlen setting}."
  else
    warn "pam_unix does not specify minlen."
    if ask_yes_no "Append minlen=$PW_MINLEN to the pam_unix password line?"; then
      backup_file "$COMMON_PASSWORD"
      sed -ri "/^[[:space:]]*password.*pam_unix\.so/ { /minlen=/! s/$/ minlen=$PW_MINLEN/; }" "$COMMON_PASSWORD"
      grep -nE '^[[:space:]]*password.*pam_unix\.so' "$COMMON_PASSWORD" || true
    fi
  fi
else
  warn "$COMMON_PASSWORD not found."
fi

# ============================================================
# 9. PAM NULL PASSWORD AUTH
# ============================================================
section "9. PAM Null Password Authentication"

COMMON_AUTH="/etc/pam.d/common-auth"

if [[ -f "$COMMON_AUTH" ]]; then
  MATCHES="$(grep -nE 'pam_unix\.so.*(nullok|nullok_secure)' "$COMMON_AUTH" 2>/dev/null || true)"

  if [[ -n "$MATCHES" ]]; then
    warn "Found null-password options:"
    printf '%s\n' "$MATCHES"

    if ask_yes_no "Remove nullok and nullok_secure from pam_unix lines?"; then
      backup_file "$COMMON_AUTH"
      sed -ri '/pam_unix\.so/ s/(^|[[:space:]])nullok_secure([[:space:]]|$)/ /g' "$COMMON_AUTH"
      sed -ri '/pam_unix\.so/ s/(^|[[:space:]])nullok([[:space:]]|$)/ /g' "$COMMON_AUTH"
      sed -ri 's/[[:space:]]+/ /g' "$COMMON_AUTH"
      ok "Removed null-password PAM options."
    fi
  else
    ok "No nullok/nullok_secure option detected in common-auth."
  fi
fi

# ============================================================
# 10. PAM FAILLOCK
# ============================================================
section "10. Account Lockout / pam_faillock"

FAILLOCK_PRESENT=0
grep -Rqs 'pam_faillock\.so' /etc/pam.d /usr/share/pam-configs 2>/dev/null && FAILLOCK_PRESENT=1

if [[ $FAILLOCK_PRESENT -eq 1 ]]; then
  ok "pam_faillock configuration is present."
  grep -Rni 'pam_faillock\.so' /etc/pam.d /usr/share/pam-configs 2>/dev/null | tee -a "$REPORT" || true
else
  warn "pam_faillock configuration was not detected."

  if ask_yes_no "Create Mint/Debian pam-auth-update faillock profiles?"; then
    backup_file /usr/share/pam-configs/faillock
    backup_file /usr/share/pam-configs/faillock_reset
    backup_file /usr/share/pam-configs/faillock_notify

    cat > /usr/share/pam-configs/faillock <<'EOF'
Name: Lockout on failed logins
Default: no
Priority: 0
Auth-Type: Primary
Auth:
        [default=die] pam_faillock.so authfail
EOF

    cat > /usr/share/pam-configs/faillock_reset <<'EOF'
Name: Reset lockout on success
Default: no
Priority: 0
Auth-Type: Additional
Auth:
        required pam_faillock.so authsucc
EOF

    cat > /usr/share/pam-configs/faillock_notify <<'EOF'
Name: Notify on account lockout
Default: no
Priority: 1024
Auth-Type: Primary
Auth:
        requisite pam_faillock.so preauth
EOF

    chmod 644 /usr/share/pam-configs/faillock \
              /usr/share/pam-configs/faillock_reset \
              /usr/share/pam-configs/faillock_notify

    echo
    warn "pam-auth-update will open an interactive menu."
    warn "Select ALL THREE:"
    echo "  [*] Notify on account lockout"
    echo "  [*] Lockout on failed logins"
    echo "  [*] Reset lockout on success"
    echo
    read -r -p "Press Enter to open pam-auth-update..." _
    pam-auth-update

    echo
    if grep -q 'pam_faillock\.so' /etc/pam.d/common-auth 2>/dev/null; then
      ok "pam_faillock is now present in common-auth."
    else
      warn "pam_faillock is still not present in common-auth. Re-run pam-auth-update and verify selections."
    fi
  fi
fi

# ============================================================
# 11. SYSCTL INCLUDING SYN COOKIES
# ============================================================
section "11. Kernel Network Hardening"

SYSCTL_KEYS=(
  net.ipv4.tcp_syncookies
  net.ipv4.ip_forward
  net.ipv4.conf.all.accept_redirects
  net.ipv4.conf.default.accept_redirects
  net.ipv4.conf.all.send_redirects
  net.ipv4.conf.all.accept_source_route
  net.ipv4.conf.default.accept_source_route
  net.ipv4.icmp_echo_ignore_broadcasts
  net.ipv4.conf.all.rp_filter
  net.ipv4.conf.default.rp_filter
)

for k in "${SYSCTL_KEYS[@]}"; do
  sysctl "$k" 2>/dev/null || true
done

SYNC="$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null || echo '?')"

if [[ "$SYNC" != "1" ]]; then
  warn "IPv4 TCP SYN cookies are not enabled."
fi

if ask_yes_no "Apply conservative network hardening including TCP SYN cookies?"; then
  SYSCTL_FILE="/etc/sysctl.d/99-cyberpatriot-hardening.conf"
  backup_file "$SYSCTL_FILE"

  cat > "$SYSCTL_FILE" <<'EOF'
net.ipv4.tcp_syncookies = 1
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
EOF

  run sysctl --system
fi

warn "Do NOT disable ip_forward if the README explicitly says this host is acting as a router."

# ============================================================
# 12. UFW
# ============================================================
section "12. Firewall"

if ! command -v ufw >/dev/null 2>&1; then
  warn "UFW is not installed."
  if ask_yes_no "Install UFW?"; then
    run apt-get update
    run apt-get install -y ufw
  fi
fi

if command -v ufw >/dev/null 2>&1; then
  ufw status verbose || true

  if ask_yes_no "Enable UFW with deny-incoming / allow-outgoing defaults?"; then
    run ufw default deny incoming
    run ufw default allow outgoing

    for p in $REQUIRED_PORTS; do
      [[ -n "$p" ]] && run ufw allow "$p"
    done

    run ufw --force enable
    run ufw status verbose
  fi
fi

# ============================================================
# 13. SERVICES INCLUDING NGINX + SQUID
# ============================================================
section "13. Services"

echo "Active services:"
systemctl list-units --type=service --state=active --no-pager 2>/dev/null | tee -a "$REPORT" || true

echo
echo "Enabled services:"
systemctl list-unit-files --type=service --state=enabled --no-pager 2>/dev/null | tee -a "$REPORT" || true

REVIEW_SERVICES=(
  nginx.service
  squid.service
  squid3.service
  apache2.service
  vsftpd.service
  proftpd.service
  pure-ftpd.service
  ssh.service
  sshd.service
  telnet.socket
  telnet.service
  xinetd.service
  rsh.socket
  rlogin.socket
  rexec.socket
  tftpd-hpa.service
  smbd.service
  nmbd.service
  cups.service
  avahi-daemon.service
  rpcbind.service
  nfs-server.service
)

for svc in "${REVIEW_SERVICES[@]}"; do
  if systemctl list-unit-files "$svc" --no-legend 2>/dev/null | grep -q .; then
    state="$(systemctl is-enabled "$svc" 2>/dev/null || true)"
    active="$(systemctl is-active "$svc" 2>/dev/null || true)"

    printf '%-24s enabled=%-12s active=%s\n' "$svc" "$state" "$active"

    if ! is_required_service "$svc"; then
      if [[ "$active" == "active" || "$state" == "enabled" ]]; then
        warn "$svc is active/enabled but is NOT listed as required."

        if ask_yes_no "Disable and stop '$svc'?"; then
          run systemctl disable --now "$svc"
        fi
      fi
    else
      ok "$svc is marked required."
    fi
  fi
done

# ============================================================
# 14. UPDATES
# ============================================================
section "14. Package Updates"

echo "Upgradeable packages:"
apt list --upgradable 2>/dev/null | tee -a "$REPORT" || true

if ask_yes_no "Run apt update and FULL upgrade now?"; then
  run apt-get update

  info "During config-file prompts, preserving the local config is often safer unless you know the maintainer version is needed."
  run env DEBIAN_FRONTEND=readline apt-get full-upgrade -y
fi

echo
if dpkg-query -W vsftpd >/dev/null 2>&1; then
  echo "Installed vsftpd version:"
  dpkg-query -W -f='${Version}\n' vsftpd 2>/dev/null || true
fi

# ============================================================
# 15. SSH
# ============================================================
section "15. SSH Hardening"

if command -v sshd >/dev/null 2>&1 || dpkg-query -W openssh-server >/dev/null 2>&1; then
  sshd -T 2>/dev/null | grep -Ei '^(permitrootlogin|permitemptypasswords|maxauthtries|x11forwarding|allowtcpforwarding|passwordauthentication|pubkeyauthentication)\b' || true

  if ask_yes_no "Install conservative SSH hardening?"; then
    mkdir -p /etc/ssh/sshd_config.d
    DROPIN="/etc/ssh/sshd_config.d/99-cyberpatriot-hardening.conf"
    backup_file "$DROPIN"

    cat > "$DROPIN" <<'EOF'
PermitRootLogin no
PermitEmptyPasswords no
MaxAuthTries 3
X11Forwarding no
EOF

    chmod 644 "$DROPIN"

    if sshd -t; then
      ok "SSH config syntax valid."
      systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
    else
      err "SSH config invalid. Restoring previous state."
      rm -f "$DROPIN"
      [[ -f "$BACKUP_DIR$DROPIN" ]] && cp -a "$BACKUP_DIR$DROPIN" "$DROPIN"
    fi
  fi
fi

warn "PasswordAuthentication is intentionally NOT changed automatically."

# ============================================================
# 16. LISTENING PORTS + BACKDOOR HUNTING
# ============================================================
section "16. Listening Ports and Backdoor Hunting"

ss -tlnp 2>/dev/null | tee -a "$REPORT" || true
echo
ss -tulpn 2>/dev/null | tee -a "$REPORT" || true

echo
echo "Python/Perl/Ruby/PHP/Netcat-like processes:"
ps -ef | grep -Ei '[p]ython|[p]erl|[r]uby|[p]hp|[n]cat|[n]c |[s]ocat' | tee -a "$REPORT" || true

echo
echo "Interpreter scripts in unusual system locations:"
find /usr/share /usr/local /opt /tmp /var/tmp \
  -xdev -type f \( -name '*.py' -o -name '*.pl' -o -name '*.rb' -o -name '*.php' -o -name '*.sh' \) \
  -print 2>/dev/null | tee "$WORKDIR/suspicious-scripts.txt" || true

echo
echo "Processes listening on uncommon high ports (>=1024):"
ss -ltnp 2>/dev/null | awk '
NR==1 {print; next}
{
  addr=$4
  n=split(addr,a,":")
  port=a[n]
  if (port ~ /^[0-9]+$/ && port >= 1024) print
}' | tee -a "$REPORT"

warn "Investigate every unexplained listener before deleting anything."

if ask_yes_no "Search for files containing common reverse-shell/backdoor indicators?"; then
  grep -RIlE \
    'socket\.socket|socket\.SOCK_STREAM|subprocess\.Popen|/bin/sh|/bin/bash|os\.system|pty\.spawn|nc -e|ncat .*--exec|socat .*EXEC' \
    /usr/share /usr/local /opt /tmp /var/tmp 2>/dev/null \
    | tee "$WORKDIR/backdoor-indicator-files.txt" || true
fi

# ============================================================
# 17. PROHIBITED MEDIA
# ============================================================
section "17. Prohibited Media"

if [[ -n "$PROHIBITED_EXTS" ]]; then
  for ext in $PROHIBITED_EXTS; do
    [[ -z "$ext" ]] && continue
    ext="${ext#.}"

    echo
    echo "Searching for *.$ext files..."

    find /home /srv /usr/games \
      -type f -iname "*.$ext" \
      -print 2>/dev/null | tee "$WORKDIR/prohibited-$ext.txt" || true

    if [[ -s "$WORKDIR/prohibited-$ext.txt" ]]; then
      warn "Potential prohibited .$ext files found."

      if ask_yes_no "Interactively review/delete these .$ext files?"; then
        while IFS= read -r f; do
          [[ -z "$f" ]] && continue
          echo "FILE: $f"
          ls -lh "$f" 2>/dev/null || true

          if ask_yes_no "Delete '$f'?"; then
            rm -f -- "$f"
          fi
        done < "$WORKDIR/prohibited-$ext.txt"
      fi
    fi
  done
else
  info "No prohibited extensions were entered."
fi

# Always show common media types for investigation.
echo
echo "Common media under /home:"
find /home -type f \( \
  -iname '*.ogg' -o -iname '*.mp3' -o -iname '*.wav' -o -iname '*.flac' -o \
  -iname '*.mp4' -o -iname '*.mkv' -o -iname '*.avi' -o -iname '*.mov' \
\) -print 2>/dev/null | tee -a "$REPORT" || true

# ============================================================
# 18. PROHIBITED ARCHIVES / TOOL SOURCES
# ============================================================
section "18. Archives and Unauthorized Tool Sources"

echo "Archives in user/system software locations:"
find /home /usr/games /opt /usr/local /tmp /var/tmp \
  -type f \( -iname '*.zip' -o -iname '*.tar' -o -iname '*.tar.gz' -o -iname '*.tgz' -o -iname '*.7z' \) \
  -print 2>/dev/null | tee "$WORKDIR/archive-files.txt" || true

warn "Archives in /usr/games, /opt, /usr/local, or unusual locations deserve special attention."

if [[ -s "$WORKDIR/archive-files.txt" ]] && ask_yes_no "Interactively review/delete suspicious archives?"; then
  while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    echo
    echo "ARCHIVE: $f"
    ls -lh "$f" 2>/dev/null || true

    if ask_yes_no "Delete '$f'?"; then
      rm -f -- "$f"
    fi
  done < "$WORKDIR/archive-files.txt"
fi

# ============================================================
# 19. UNAUTHORIZED / HACKING SOFTWARE
# ============================================================
section "19. Installed Software Review"

COMMON_REVIEW_PKGS=(
  doona
  xprobe
  xprobe2
  ophcrack
  john
  hydra
  nikto
  medusa
  nmap
  zenmap
  netcat-traditional
  netcat-openbsd
  ncat
  wireshark
  tshark
  tcpdump
  aircrack-ng
  ettercap-common
  ettercap-graphical
  metasploit-framework
  sqlmap
  hashcat
  crunch
  reaver
  kismet
  telnet
  telnetd
  rsh-client
  rsh-server
  talk
  talkd
)

declare -A SEEN_PKGS=()

echo "Installed packages worth reviewing:"
for p in "${COMMON_REVIEW_PKGS[@]}" $PROHIBITED_PKGS; do
  [[ -z "$p" ]] && continue
  [[ -n "${SEEN_PKGS[$p]+x}" ]] && continue
  SEEN_PKGS["$p"]=1

  if dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q 'install ok installed'; then
    echo "  INSTALLED: $p"

    if contains_line "$p" "$PROHIBITED_PKGS"; then
      warn "$p was explicitly entered as prohibited."
      ask_yes_no "Purge prohibited package '$p'?" && run apt-get purge -y "$p"
    else
      if ask_yes_no "Is '$p' unauthorized on this image and should it be purged?"; then
        run apt-get purge -y "$p"
      fi
    fi
  fi
done

warn "Tools such as nmap, Wireshark, and tcpdump are not automatically bad. Keep them if required."

# ============================================================
# 20. CRON / SYSTEMD / STARTUP PERSISTENCE
# ============================================================
section "20. Persistence Checks"

echo "--- /etc/crontab ---"
cat /etc/crontab 2>/dev/null || true

echo
echo "--- cron files ---"
find /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly \
  -maxdepth 1 -type f -print 2>/dev/null | sort || true

echo
echo "--- user crontabs ---"
for u in $(cut -d: -f1 /etc/passwd); do
  CRON="$(crontab -u "$u" -l 2>/dev/null || true)"
  if [[ -n "$CRON" ]]; then
    echo "[$u]"
    printf '%s\n' "$CRON"
  fi
done

echo
echo "--- systemd timers ---"
systemctl list-timers --all --no-pager 2>/dev/null || true

echo
echo "--- local service/timer files ---"
find /etc/systemd/system \
  -type f \( -name '*.service' -o -name '*.timer' \) \
  -print 2>/dev/null | sort || true

echo
echo "--- shell startup files ---"
find /home /root \
  -maxdepth 3 -type f \( \
    -name '.bashrc' -o -name '.profile' -o -name '.bash_profile' -o \
    -name '.xprofile' -o -name '.xsessionrc' \
  \) -print 2>/dev/null || true

echo
echo "--- desktop autostart ---"
find /etc/xdg/autostart /home \
  -type f -name '*.desktop' -path '*autostart*' -print 2>/dev/null || true

# ============================================================
# 21. SUDOERS
# ============================================================
section "21. Sudoers"

grep -RhnE '^[[:space:]]*[^#].*(ALL|NOPASSWD)' \
  /etc/sudoers /etc/sudoers.d 2>/dev/null | tee -a "$REPORT" || true

if command -v visudo >/dev/null 2>&1; then
  if visudo -c; then
    ok "sudoers syntax valid."
  else
    err "sudoers syntax error detected."
  fi
fi

# ============================================================
# 22. FILE PERMISSIONS
# ============================================================
section "22. File Permissions"

echo "Sensitive files:"
stat -c '%a %U:%G %n' \
  /etc/passwd /etc/shadow /etc/group /etc/gshadow 2>/dev/null || true

echo
echo "World-writable regular files:"
find / -xdev -type f -perm -0002 -print 2>/dev/null | tee "$WORKDIR/world-writable-files.txt" || true

echo
echo "World-writable directories without sticky bit:"
find / -xdev -type d -perm -0002 ! -perm -1000 -print 2>/dev/null | tee "$WORKDIR/world-writable-dirs.txt" || true

echo
echo "SUID files:"
find / -xdev -type f -perm -4000 -print 2>/dev/null | tee "$WORKDIR/suid-files.txt" || true

echo
echo "SGID files:"
find / -xdev -type f -perm -2000 -print 2>/dev/null | tee "$WORKDIR/sgid-files.txt" || true

warn "Do not bulk chmod or delete SUID/SGID files."

# ============================================================
# 23. FTP / APACHE / SAMBA SERVICE-SPECIFIC CHECKS
# ============================================================
section "23. Critical Service Configuration"

if [[ -f /etc/vsftpd.conf ]]; then
  echo "VSFTPD:"
  grep -Ein '^(anonymous_enable|local_enable|write_enable|chroot_local_user|allow_writeable_chroot|listen|listen_ipv6)' \
    /etc/vsftpd.conf 2>/dev/null || true
fi

if systemctl list-unit-files apache2.service --no-legend 2>/dev/null | grep -q .; then
  echo
  echo "Apache:"
  apache2ctl -M 2>/dev/null || true
  grep -RniE 'Options .*Indexes|ServerTokens|ServerSignature' /etc/apache2 2>/dev/null || true
fi

if command -v testparm >/dev/null 2>&1; then
  echo
  echo "Samba:"
  testparm -s 2>/dev/null || true
fi

# ============================================================
# 24. LOGIN / AUTH
# ============================================================
section "24. Login and Authentication"

echo "Login-capable accounts:"
awk -F: '$7 !~ /(nologin|false)$/ {print $1 ":" $3 ":" $6 ":" $7}' /etc/passwd

echo
echo "Root status:"
passwd -S root 2>/dev/null || true

echo
echo "Recent logins:"
last -a 2>/dev/null | head -n 30 || true

echo
echo "Recent failed logins:"
lastb -a 2>/dev/null | head -n 30 || true

if dpkg-query -W lightdm >/dev/null 2>&1; then
  echo
  echo "LightDM guest/autologin settings:"
  grep -RniE 'allow-guest|autologin' /etc/lightdm 2>/dev/null || true

  if ask_yes_no "Disable LightDM guest login?"; then
    mkdir -p /etc/lightdm/lightdm.conf.d
    CFG="/etc/lightdm/lightdm.conf.d/99-cyberpatriot.conf"
    backup_file "$CFG"

    cat > "$CFG" <<'EOF'
[Seat:*]
allow-guest=false
EOF

    chmod 644 "$CFG"
  fi
fi

# ============================================================
# 25. PROCESSES
# ============================================================
section "25. Processes"

echo "Root processes:"
ps -U root -u root u 2>/dev/null | tee -a "$REPORT" || true

echo
echo "Highest CPU:"
ps aux --sort=-%cpu 2>/dev/null | head -n 25 | tee -a "$REPORT" || true

echo
echo "Processes with deleted executables:"
find /proc/[0-9]*/exe -lname '* (deleted)' -printf '%p -> %l\n' 2>/dev/null | tee -a "$REPORT" || true

# ============================================================
# 26. LOGS
# ============================================================
section "26. Security Logs"

if [[ -f /var/log/auth.log ]]; then
  tail -n 150 /var/log/auth.log | tee -a "$REPORT"
else
  journalctl -n 150 --no-pager 2>/dev/null | tee -a "$REPORT" || true
fi

echo
echo "Failed units:"
systemctl --failed --no-pager 2>/dev/null | tee -a "$REPORT" || true

# ============================================================
# 27. FINAL VERIFICATION
# ============================================================
section "27. Final Verification"

echo "--- Users ---"
awk -F: '
{
  user=$1; uid=$3; home=$6; shell=$7;
  login=(shell !~ /(nologin|false)$/);
  homedir=(home ~ /^\/home\//);
  if ((uid >= 1000 && user != "nobody") || (login && homedir))
    printf "%-20s uid=%-6s home=%-25s shell=%s\n", user,uid,home,shell
}' /etc/passwd

echo
echo "--- Sudo ---"
getent group sudo || true

echo
echo "--- Root password state ---"
passwd -S root 2>/dev/null || true

echo
echo "--- PAM min length ---"
grep -nE '^[[:space:]]*password.*pam_unix\.so' /etc/pam.d/common-password 2>/dev/null || true

echo
echo "--- PAM null password options ---"
grep -nE 'pam_unix\.so.*(nullok|nullok_secure)' /etc/pam.d/common-auth 2>/dev/null || true

echo
echo "--- PAM faillock ---"
grep -Rni 'pam_faillock\.so' /etc/pam.d /usr/share/pam-configs 2>/dev/null || true

echo
echo "--- SYN cookies ---"
sysctl net.ipv4.tcp_syncookies 2>/dev/null || true

echo
echo "--- Firewall ---"
ufw status verbose 2>/dev/null || true

echo
echo "--- Listening ports ---"
ss -tulpn 2>/dev/null || true

echo
echo "--- Required services ---"
for svc in $REQUIRED_SERVICES; do
  [[ -z "$svc" ]] && continue

  if systemctl is-active --quiet "$svc" 2>/dev/null; then
    ok "Required service active: $svc"
  else
    warn "Required service NOT active: $svc"
  fi
done

echo
echo "--- SSH validation ---"
if command -v sshd >/dev/null 2>&1; then
  sshd -t && ok "sshd configuration valid." || err "sshd configuration INVALID."
fi

echo
echo "--- sudoers validation ---"
if command -v visudo >/dev/null 2>&1; then
  visudo -c >/dev/null 2>&1 && ok "sudoers configuration valid." || err "sudoers configuration INVALID."
fi

# ============================================================
# 28. MANUAL CHECKLIST
# ============================================================
section "28. Manual Checks Still Required"

cat <<'EOF' | tee -a "$REPORT"
[ ] Re-read every Forensics Question before deleting evidence.
[ ] Re-read README after completing automated checks.
[ ] Confirm EVERY authorized user and administrator.
[ ] Confirm README-requested groups and exact memberships.
[ ] Confirm critical services remain running.
[ ] Confirm files required by FTP/web/Samba services remain intact.
[ ] Inspect every unexplained listening port.
[ ] Inspect unusual low-UID accounts with login shells/home directories.
[ ] Inspect cron jobs, timers, startup files, and autostart entries.
[ ] Inspect strange Python/Perl/Ruby/PHP/shell scripts.
[ ] Inspect archives under /usr/games, /opt, /usr/local, /tmp, and /var/tmp.
[ ] Inspect unauthorized/security-testing tools not required by README.
[ ] Inspect world-writable files/directories.
[ ] Inspect unusual SUID/SGID binaries.
[ ] Inspect browser extensions/settings if relevant.
[ ] Inspect FTP, SSH, Apache, Samba, DNS, mail, or other required service configs.
[ ] Verify software updates completed successfully.
[ ] Check the CyberPatriot scoring report after each major change.
[ ] Stop if points decrease and use backups/logs to determine why.
EOF

echo
echo "${GREEN}${BOLD}Finished.${RESET}"
echo "Log:       $LOG"
echo "Report:    $REPORT"
echo "Backups:   $BACKUP_DIR"
echo "Baseline:  $WORKDIR/baseline.txt"
