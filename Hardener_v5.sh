#!/usr/bin/env bash
# ============================================================
# CyberPatriot Linux Mint / Ubuntu Interactive Hardening Tool
# Version 5.0
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
#   sudo bash CyberPatriot_Mint_Hardener_v5.sh
#
# Audit-only:
#   sudo bash CyberPatriot_Mint_Hardener_v5.sh --audit
# ============================================================

set -uo pipefail
umask 077
if [[ $EUID -ne 0 ]]; then echo "Run with sudo bash $0" >&2; exit 1; fi
case "${1:-}" in ""|--audit) ;; *) echo "Usage: sudo bash $0 [--audit]" >&2; exit 2;; esac
IFS=$'\n\t'

AUDIT_ONLY=0
[[ "${1:-}" == "--audit" ]] && AUDIT_ONLY=1

TS="$(date +%Y%m%d_%H%M%S)_$$"
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
  case "$prompt" in
    "Set login.defs"*|"Remove nullok/nullok_secure?"|"Set net.ipv4.tcp_syncookies="*|"Install UFW?"|"Enable UFW with deny-incoming / allow-outgoing defaults?"|"Run apt update and upgrade without package removals now?") return 0;;
  esac

  if [[ "$default" == "Y" ]]; then
    read -r -p "$prompt [Y/n]: " ans || return 1
    ans="${ans:-Y}"
  else
    read -r -p "$prompt [y/N]: " ans || return 1
    ans="${ans:-N}"
  fi

  [[ "$ans" =~ ^[Yy]$ ]]
}

run(){
  [[ $AUDIT_ONLY -eq 1 ]] && { info "AUDIT: would run $*"; return 0; }
  local pretty
  printf -v pretty '%q ' "$@"
  log "+ $pretty"
  "$@" 2>&1 | tee -a "$LOG"
  return "${PIPESTATUS[0]}"
}

backup_file(){
  local f="$1"
  if [[ -e "$f" ]]; then
    local dest="$BACKUP_DIR${f}"
    mkdir -p "$(dirname "$dest")"
    [[ -e "$dest" || -L "$dest" ]] && return 0
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

safe_purge(){
  local p="$1" sim protected dep
  [[ $AUDIT_ONLY -eq 1 ]] && return 0
  sim="$(apt-get -s purge -- "$p" 2>&1)" || { warn "Purge simulation failed for $p"; return 1; }
  printf '%s\n' "$sim" | tee -a "$LOG"
  protected="$(printf '%s\n%s\n' "$REQUIRED_APPS" "$REQUIRED_SERVICES" | sed -E 's/\.(service|socket)$//')"
  while read -r dep; do
    dep="${dep%%:*}"
    if contains_line "$dep" "$protected"; then warn "Removal would remove required $dep; refused."; return 1; fi
  done < <(awk '$1=="Remv" || $1=="Purg" {print $2}' <<< "$sim")
  ask_yes_no "Approve this removal plan for $p after checking required-service dependencies?" || return 0
  run apt-get purge -y -- "$p"
}

is_protected_path(){
  local p
  p="$(readlink -m -- "$1")"
  case "$p" in /opt/CyberPatriot*|/opt/cyberpatriot*|/opt/CCS*|/root/cp-hardener-*|*/cp-evidence-*|"$WORKDIR"/*) return 0;; esac
  [[ "${p,,}" == *forensic* || "${p,,}" == *cyberpatriot* || "${p,,}" == *scoring* ]]
}
set_kv(){
  local file="$1" key="$2" value="$3"
  [[ $AUDIT_ONLY -eq 1 ]] && return 0
  backup_file "$file"
  # Keys here are fixed, trusted configuration directives.
  sed -i -E "/^[[:space:]]*${key}[[:space:]]*=/d" "$file"
  printf '%s=%s\n' "$key" "$value" >> "$file"
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
echo "${BOLD}CyberPatriot Linux Mint / Ubuntu Hardening Tool v5.0${RESET}"
echo "Work directory: $WORKDIR"
warn "READ FORENSICS QUESTIONS BEFORE CHANGING THE IMAGE."
warn "READ THE README BEFORE CHANGING USERS, GROUPS, SERVICES, OR FILES."
warn "Never modify /opt/CyberPatriot or scoring-related files."
[[ $AUDIT_ONLY -eq 1 ]] && warn "AUDIT MODE ENABLED: changes will not be offered."
# Full console output is retained alongside the focused report and change log.
exec > >(tee -a "$WORKDIR/transcript.txt") 2>&1

# ============================================================
# 1. SYSTEM INFO
# ============================================================
if [[ ! -t 0 ]]; then err "Use an interactive terminal for README inputs."; exit 2; fi
if [[ $AUDIT_ONLY -eq 0 ]]; then
  ask_yes_no "Have you read the README, saved forensic answers/evidence, and confirmed local console/admin access?" || exit 0
fi
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

read -r -p "Required application package names (not services): " REQUIRED_APPS_RAW
REQUIRED_APPS="$(parse_list "$REQUIRED_APPS_RAW")"
ROUTING_REQUIRED=0
SSH_PASSWORD_ONLY=0
ask_yes_no "Does the README require IPv4 routing/forwarding?" && ROUTING_REQUIRED=1
ask_yes_no "Does the README require password-only SSH/SFTP (no keys)?" && SSH_PASSWORD_ONLY=1
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
for n in PASS_MAX_DAYS PASS_MIN_DAYS PASS_WARN_AGE PW_MINLEN; do
  [[ "${!n}" =~ ^[0-9]+$ ]] || { err "Invalid numeric setting: $n"; exit 2; }
done
(( PASS_MAX_DAYS >= PASS_MIN_DAYS && PW_MINLEN >= 8 )) || { err "Inconsistent password settings"; exit 2; }
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
  echo "--- installed packages ---"
  dpkg-query -W 2>/dev/null || true
  echo "--- manual packages ---"
  apt-mark showmanual 2>/dev/null || true
  echo "--- held packages ---"
  apt-mark showhold 2>/dev/null || true
  echo "--- processes ---"
  ps auxww
  echo "--- ufw ---"
  ufw status verbose 2>/dev/null || true
} > "$WORKDIR/baseline.txt"

chmod 600 "$WORKDIR/baseline.txt"
if [[ $AUDIT_ONLY -eq 0 ]]; then
  for f in /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/login.defs /etc/sudoers /etc/pam.d/common-auth /etc/pam.d/common-password /etc/pam.d/common-account /etc/pam.d/common-session /etc/hosts /etc/rc.local; do backup_file "$f"; done
fi
# Preserve selected forensic sources before account/package/config changes.
mkdir -p "$WORKDIR/evidence"
for f in /var/log/auth.log /var/log/syslog /var/log/wtmp /var/log/btmp /etc/crontab /etc/rc.local /etc/hosts; do
  [[ -f "$f" ]] && cp -a --parents "$f" "$WORKDIR/evidence/"
done
for d in /etc/cron.d /var/spool/cron/crontabs /etc/systemd/system; do
  [[ -d "$d" ]] && cp -a --parents "$d" "$WORKDIR/evidence/"
done
journalctl --no-pager -n 3000 > "$WORKDIR/evidence/journal.txt" 2>/dev/null || true
ok "Baseline and selected evidence saved to $WORKDIR; this is not a complete forensic disk image."

# ============================================================
# 4. USERS INCLUDING HIDDEN LOW-UID USERS
# Official-key methods: deluser --remove-home; gpasswd -d USER sudo
# ============================================================
section "4. Users and Administrators"

echo "All user-like accounts (ANY account with /home plus UID>=1000 accounts):"
SUSPECT_USER_LIST="$(awk -F: '$1!="nobody" && ($3>=1000 || $6 ~ /^\/home\//) {print $1}' /etc/passwd | sort -u)"
printf '  %s
' $SUSPECT_USER_LIST 2>/dev/null || true

if [[ -n "$ALL_AUTHORIZED" ]]; then
  for u in $SUSPECT_USER_LIST; do
    [[ -z "$u" ]] && continue
    if ! contains_line "$u" "$ALL_AUTHORIZED"; then
      [[ "$u" == "${SUDO_USER:-root}" ]] && { warn "Current operator $u excluded from deletion; reconcile README manually."; continue; }
      uid="$(id -u "$u" 2>/dev/null || echo '?')"
      home="$(getent passwd "$u" | cut -d: -f6)"
      shell="$(getent passwd "$u" | cut -d: -f7)"
      warn "Potential unauthorized account: $u (uid=$uid home=$home shell=$shell)"
      if ask_yes_no "Remove '$u' with: deluser --remove-home $u ?"; then
        run deluser --remove-home "$u"
      fi
    fi
  done
fi

echo; echo "Current sudo group:"; getent group sudo || true
for u in $AUTH_ADMINS; do
  [[ -z "$u" ]] && continue
  if ! id "$u" >/dev/null 2>&1; then
    warn "Authorized administrator '$u' does not exist."
    ask_yes_no "Create '$u'?" && adduser "$u"
  fi
  if id "$u" >/dev/null 2>&1 && ! id -nG "$u" | tr ' ' '
' | grep -Fxq sudo; then
    warn "$u should be an administrator but is not in sudo."
    ask_yes_no "Add '$u' to sudo?" && run usermod -aG sudo "$u"
  fi
done
for u in $AUTH_USERS; do
  [[ -z "$u" ]] && continue
  if ! id "$u" >/dev/null 2>&1; then
    warn "Missing authorized standard account: $u"
    ask_yes_no "Create authorized standard user $u?" && run adduser "$u"
  fi
  if id "$u" >/dev/null 2>&1 && id -nG "$u" | tr ' ' '
' | grep -Fxq sudo; then
    warn "$u is a standard user but has sudo."
    ask_yes_no "Remove '$u' using: gpasswd -d $u sudo ?" && run gpasswd -d "$u" sudo
  fi
done

echo; echo "Mint nopasswdlogin group:" 
if getent group nopasswdlogin >/dev/null 2>&1; then
  getent group nopasswdlogin
  for u in $(getent group nopasswdlogin | cut -d: -f4 | tr ',' '\n'); do
    [[ -z "$u" ]] && continue
    warn "$u is in nopasswdlogin (passwordless graphical login capability)."
    ask_yes_no "Remove '$u' from nopasswdlogin?" && run gpasswd -d "$u" nopasswdlogin
  done
fi

echo; echo "UID 0 accounts:"; awk -F: '$3==0{print $1}' /etc/passwd
for u in $(awk -F: '$3==0{print $1}' /etc/passwd); do
  [[ "$u" == root ]] && continue
  warn "NON-ROOT UID 0 account: $u. Password lock alone does not remove privileges. Resolve UID and ownership using the guide."
  ask_yes_no "Lock '$u'?" && run passwd -l "$u"
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
  info "Root has a password hash. Lock root unless the README requires root password login."
  ask_yes_no "Lock root password (confirm working sudo administrator first)?" && run passwd -l root
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

APPLY_STANDARD=0
ask_yes_no "Apply password aging to ALL authorized standard users?" Y && APPLY_STANDARD=1
for u in $ALL_AUTHORIZED; do
  [[ -z "$u" ]] && continue
  id "$u" >/dev/null 2>&1 || continue
  chage -l "$u" 2>/dev/null || true
  if contains_line "$u" "$AUTH_ADMINS"; then
    ask_yes_no "Apply password aging to administrator '$u'?" && run chage -M "$PASS_MAX_DAYS" -m "$PASS_MIN_DAYS" -W "$PASS_WARN_AGE" "$u"
  elif [[ $APPLY_STANDARD -eq 1 ]]; then
    run chage -M "$PASS_MAX_DAYS" -m "$PASS_MIN_DAYS" -W "$PASS_WARN_AGE" "$u"
  fi
done

# ============================================================
# 8. PAM MINIMUM LENGTH
# Use pwquality for enforceable strength checks; do not rely on pam_unix minlen alone.
# ============================================================
section "8. Password Quality and History"
if [[ $AUDIT_ONLY -eq 0 ]]; then
  if command -v python3 >/dev/null && command -v pam-auth-update >/dev/null; then
    run apt-get install -y libpam-pwquality
    if find /lib /usr/lib -name pam_pwquality.so -print -quit 2>/dev/null | grep -q . && find /lib /usr/lib -name pam_pwhistory.so -print -quit 2>/dev/null | grep -q .; then
      backup_file /etc/pam.d/common-password
      backup_file /usr/share/pam-configs/cp-password-policy
      # Preserve profile ordering using pam-auth-update rather than appending after pam_deny.
      cat > /usr/share/pam-configs/cp-password-policy <<EOF
Name: CyberPatriot password quality and history
Default: yes
Priority: 1025
Password-Type: Primary
Password:
        requisite pam_pwquality.so retry=3 minlen=$PW_MINLEN difok=3 minclass=3 maxrepeat=2 dictcheck=1 dcredit=0 ucredit=0 lcredit=0 ocredit=0 enforce_for_root
        requisite pam_pwhistory.so use_authtok remember=12 enforce_for_root
Password-Initial:
        requisite pam_pwquality.so retry=3 minlen=$PW_MINLEN difok=3 minclass=3 maxrepeat=2 dictcheck=1 dcredit=0 ucredit=0 lcredit=0 ocredit=0 enforce_for_root
        requisite pam_pwhistory.so use_authtok remember=12 enforce_for_root
EOF
      chmod 644 /usr/share/pam-configs/cp-password-policy
      warn "PAM changes affect login/password changes. Keep console and an existing sudo shell open."
      run pam-auth-update --disable pwquality --enable cp-password-policy
      grep -nE 'pam_pwquality|pam_pwhistory|pam_unix' /etc/pam.d/common-password
      if ! grep -qE '^[[:space:]]*password.*pam_pwquality.so' /etc/pam.d/common-password; then
        warn "PAM local changes prevented policy activation. Use pam-auth-update interactively; do not force over a custom stack."
      fi
    else warn "Quality/history modules unavailable; policy not installed."; fi
  else warn "python3/pam-auth-update missing; review PAM manually."; fi
fi
COMMON_PASSWORD=/etc/pam.d/common-password
# Retain v3's explicit pam_unix length option for practice-image compatibility;
# pwquality/pwhistory additionally enforce strength, history and root changes.
if [[ $AUDIT_ONLY -eq 0 && -f "$COMMON_PASSWORD" ]]; then
  backup_file "$COMMON_PASSWORD"
  sed -ri "/^[[:space:]]*password.*pam_unix\\.so/ { s/[[:space:]]+minlen=[0-9]+//g; s/$/ minlen=$PW_MINLEN/; }" "$COMMON_PASSWORD"
fi
grep -nE '^[[:space:]]*password.*pam_(pwquality|pwhistory|unix)' "$COMMON_PASSWORD" 2>/dev/null || true

# ============================================================
# 9. PAM NULL PASSWORD AUTH
# Official key: remove nullok from pam_unix.so in common-auth
# ============================================================
section "9. PAM Null Password Authentication"
COMMON_AUTH="/etc/pam.d/common-auth"
if [[ -f "$COMMON_AUTH" ]]; then
  grep -nE '^[[:space:]]*auth.*pam_unix\.so' "$COMMON_AUTH" || true
  if grep -E '^[[:space:]]*auth.*pam_unix\.so' "$COMMON_AUTH" | grep -qE '(^|[[:space:]])nullok(_secure)?([[:space:]]|$)'; then
    warn "nullok/nullok_secure found."
    if ask_yes_no "Remove nullok/nullok_secure?"; then
      backup_file "$COMMON_AUTH"
      sed -ri '/pam_unix\.so/ s/[[:space:]]+nullok_secure([[:space:]]|$)/ /g' "$COMMON_AUTH"
      sed -ri '/pam_unix\.so/ s/[[:space:]]+nullok([[:space:]]|$)/ /g' "$COMMON_AUTH"
    fi
  fi
  if grep -E '^[[:space:]]*auth.*pam_unix\.so' "$COMMON_AUTH" | grep -qE '(^|[[:space:]])nullok(_secure)?([[:space:]]|$)'; then
    warn "nullok still present after attempted fix."
  else
    ok "nullok/nullok_secure absent."
  fi
fi

# ============================================================
# 10. PAM FAILLOCK
# Exact profile text from official answer key + pam-auth-update
# ============================================================
section "10. Account Lockout / pam_faillock"
if ! grep -q 'pam_faillock\.so' /etc/pam.d/common-auth 2>/dev/null; then
  warn "pam_faillock is not active."
  if ask_yes_no "Configure supported pam_faillock profiles (keep current admin session open)?"; then
    if ! find /lib /usr/lib -name pam_faillock.so -print -quit 2>/dev/null | grep -q .; then warn "pam_faillock.so missing; skipping profile creation."; else
    backup_file /etc/security/faillock.conf
    touch /etc/security/faillock.conf
    set_kv /etc/security/faillock.conf deny 5
    set_kv /etc/security/faillock.conf unlock_time 900
    set_kv /etc/security/faillock.conf fail_interval 900
    for f in /usr/share/pam-configs/faillock /usr/share/pam-configs/faillock_reset /usr/share/pam-configs/faillock_notify; do backup_file "$f"; done
    touch /usr/share/pam-configs/faillock
    cat > /usr/share/pam-configs/faillock <<'EOF'
Name: Lockout on failed logins
Default: no
Priority: 0
Auth-Type: Primary
Auth:
        [default=die] pam_faillock.so authfail
EOF
    touch /usr/share/pam-configs/faillock_reset
    cat > /usr/share/pam-configs/faillock_reset <<'EOF'
Name: Reset lockout on success
Default: no
Priority: 0
Auth-Type: Additional
Auth:
        required pam_faillock.so authsucc
EOF
    touch /usr/share/pam-configs/faillock_notify
    cat > /usr/share/pam-configs/faillock_notify <<'EOF'
Name: Notify on account lockout
Default: no
Priority: 1024
Auth-Type: Primary
Auth:
        requisite pam_faillock.so preauth
EOF
    chmod 644 /usr/share/pam-configs/faillock /usr/share/pam-configs/faillock_reset /usr/share/pam-configs/faillock_notify
    echo; echo "pam-auth-update will open. Use SPACE to select ALL THREE:" 
    echo "  [*] Notify on account lockout"
    echo "  [*] Lockout on failed logins"
    echo "  [*] Reset lockout on success"
    read -r -p "Press Enter to open pam-auth-update..." _
    pam-auth-update
    if ! grep -q 'pam_faillock\.so' /etc/pam.d/common-auth 2>/dev/null; then
      warn "faillock still not active."
      if ask_yes_no "Open pam-auth-update again?"; then pam-auth-update; fi
    fi
    fi
  fi
fi
echo "Verification:"; grep -n 'pam_faillock\.so' /etc/pam.d/common-auth 2>/dev/null || true
if grep -q 'pam_faillock\.so.*preauth' /etc/pam.d/common-auth 2>/dev/null && grep -q 'pam_faillock\.so.*authfail' /etc/pam.d/common-auth 2>/dev/null && grep -q 'pam_faillock\.so.*authsucc' /etc/pam.d/common-auth 2>/dev/null; then
  ok "All three faillock components active."
else
  warn "Complete faillock stack NOT verified."
fi

# ============================================================
# 11. SYN COOKIES / SYSCTL
# Official key edits /etc/sysctl.conf then runs sysctl --system
# ============================================================
section "11. Kernel Network Hardening"
echo "tcp_syncookies definitions:" 
grep -RnsE '^[[:space:]]*net\.ipv4\.tcp_syncookies[[:space:]]*=' /etc/sysctl.conf /etc/sysctl.d /usr/lib/sysctl.d 2>/dev/null || true
echo "Runtime:"; sysctl net.ipv4.tcp_syncookies 2>/dev/null || true
if [[ "$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null || echo 0)" != 1 ]] || grep -qE '^[[:space:]]*net\.ipv4\.tcp_syncookies[[:space:]]*=[[:space:]]*0' /etc/sysctl.conf 2>/dev/null; then
  warn "SYN cookies are disabled or overridden."
  if ask_yes_no "Set net.ipv4.tcp_syncookies=1 in /etc/sysctl.conf and apply with sysctl --system?"; then
    backup_file /etc/sysctl.conf
    if grep -qE '^[[:space:]]*net\.ipv4\.tcp_syncookies[[:space:]]*=' /etc/sysctl.conf; then
      sed -ri 's/^[[:space:]]*net\.ipv4\.tcp_syncookies[[:space:]]*=.*/net.ipv4.tcp_syncookies=1/' /etc/sysctl.conf
    else
      printf '
net.ipv4.tcp_syncookies=1
' >> /etc/sysctl.conf
    fi
    if [[ -f /etc/sysctl.d/99-sysctl.conf && ! -L /etc/sysctl.d/99-sysctl.conf ]] && grep -qE '^[[:space:]]*net\.ipv4\.tcp_syncookies[[:space:]]*=[[:space:]]*0' /etc/sysctl.d/99-sysctl.conf; then
      backup_file /etc/sysctl.d/99-sysctl.conf
      sed -ri 's/^[[:space:]]*net\.ipv4\.tcp_syncookies[[:space:]]*=.*/net.ipv4.tcp_syncookies=1/' /etc/sysctl.d/99-sysctl.conf
    fi
    run sysctl --system
  fi
fi
if [[ "$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null || echo 0)" == 1 ]]; then ok "TCP SYN cookies enabled."; else err "TCP SYN cookies still disabled."; fi

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
    if [[ -n "${SSH_CONNECTION:-}" && -z "$REQUIRED_PORTS" ]]; then
      warn "Remote SSH and no required ports entered; firewall enable skipped to prevent lockout."
    else
    run ufw default deny incoming
    run ufw default allow outgoing

    for p in $REQUIRED_PORTS; do
      [[ -n "$p" ]] && run ufw allow "$p"
    done

    run ufw --force enable
    run ufw status verbose
    fi
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
  mysql.service
  mariadb.service
  bind9.service
  named.service
  postfix.service
  exim4.service
  dovecot.service
  inetutils-inetd.service
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

if ask_yes_no "Run apt update and upgrade without package removals now?"; then
  run apt-get update

  info "During config-file prompts, preserving the local config is often safer unless you know the maintainer version is needed."
  run env DEBIAN_FRONTEND=readline apt-get upgrade --with-new-pkgs -y
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
if command -v sshd >/dev/null 2>&1; then
  sshd -T 2>/dev/null | grep -Ei '^(permitrootlogin|permitemptypasswords|maxauthtries|x11forwarding|passwordauthentication|pubkeyauthentication)' || true
  if [[ $AUDIT_ONLY -eq 0 ]]; then
    DROPIN=/etc/ssh/sshd_config.d/00-cyberpatriot-hardening.conf
    backup_file /etc/ssh/sshd_config
    backup_file "$DROPIN"
    mkdir -p /etc/ssh/sshd_config.d
    cat > "$DROPIN" <<'EOF'
PermitRootLogin no
PermitEmptyPasswords no
MaxAuthTries 3
X11Forwarding no
EOF
    if [[ $SSH_PASSWORD_ONLY -eq 1 ]]; then
      printf 'PasswordAuthentication yes\nPubkeyAuthentication no\n' >> "$DROPIN"
    fi
    chmod 644 "$DROPIN"
    # Explicit first include also works when the original config has no wildcard Include.
    sed -i '\|^Include /etc/ssh/sshd_config.d/00-cyberpatriot-hardening.conf$|d' /etc/ssh/sshd_config
    sed -i '1i Include /etc/ssh/sshd_config.d/00-cyberpatriot-hardening.conf' /etc/ssh/sshd_config
    if sshd -t; then
      sshd -T | grep -Ei '^(permitrootlogin|permitemptypasswords|maxauthtries|x11forwarding|passwordauthentication|pubkeyauthentication)'
      run systemctl reload ssh || run systemctl reload sshd || warn "SSH reload failed; investigate."
    else
      err "SSH validation failed; restoring both files."
      cp -a "$BACKUP_DIR/etc/ssh/sshd_config" /etc/ssh/sshd_config
      rm -f "$DROPIN"
      [[ -f "$BACKUP_DIR$DROPIN" ]] && cp -a "$BACKUP_DIR$DROPIN" "$DROPIN"
    fi
  fi
fi
warn "Review Match blocks with sshd -T -C user=USER,host=HOST,addr=IP; global output alone does not verify each user."

# ============================================================
# 16. LISTENING PORTS + BACKDOOR HUNTING
# Official key: ss -tlnp ; ps -ef | grep python
# Remediation pattern: rm -f SCRIPT ; pkill -f SCRIPTNAME
# ============================================================
section "16. Listening Ports and Backdoor Hunting"
echo "--- ss -tlnp ---"; ss -tlnp 2>/dev/null | tee -a "$REPORT" || true
echo; echo "--- ps -ef | grep python ---"; ps -ef | grep '[p]ython' | tee -a "$REPORT" || true
SUSPICIOUS_PY="$(ps -ef | grep '[p]ython' | grep -vE 'networkd-dispatcher|blueman|system-config-printer' || true)"
if [[ -n "$SUSPICIOUS_PY" ]]; then
  warn "Unrecognized Python process(es) detected:"
  printf '%s
' "$SUSPICIOUS_PY"
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    script_path="$(grep -oE '/[^ ]+\.py' <<< "$line" | head -1 || true)"
    [[ -z "$script_path" ]] && continue
    echo "Candidate script: $script_path"
    if [[ -f "$script_path" ]] && ask_yes_no "Is this a backdoor? Preserve this file as confirmed backdoor evidence?"; then
      backup_file "$script_path"
      warn "Identify the exact PID and stop its persistence using the guide, then remove this file manually. No broad pkill performed."
    fi
  done <<< "$SUSPICIOUS_PY"
fi
echo; echo "Listener verification:"; ss -tlnp 2>/dev/null || true

# ============================================================
# 17. PROHIBITED MEDIA
# Official key searches OGG with locate; generic follow-up scans other media
# ============================================================
section "17. Prohibited Media"
if command -v locate >/dev/null 2>&1; then locate '*.ogg' 2>/dev/null | tee "$WORKDIR/ogg-files.txt" || true; else find /home -type f -iname '*.ogg' -print 2>/dev/null | tee "$WORKDIR/ogg-files.txt" || true; fi
if [[ -s "$WORKDIR/ogg-files.txt" ]]; then
  warn "OGG files found. If README prohibits non-work media, these require review."
  if ask_yes_no "Does the README prohibit this media and should these OGG files be reviewed for deletion?"; then
    while IFS= read -r f; do [[ -f "$f" ]] || continue; is_protected_path "$f" && continue; ls -lh "$f"; if ask_yes_no "Delete '$f'?"; then backup_file "$f"; rm -f -- "$f"; fi; done < "$WORKDIR/ogg-files.txt"
  fi
fi
echo; echo "Other common media under /home:" 
find /home -type f \( -iname '*.mp3' -o -iname '*.wav' -o -iname '*.flac' -o -iname '*.mp4' -o -iname '*.mkv' -o -iname '*.avi' -o -iname '*.mov' -o -iname '*.m4a' \) -print 2>/dev/null | tee -a "$REPORT" || true

# ============================================================
# 18. PROHIBITED ARCHIVES / TOOL SOURCES
# Official key searches ZIP archives with locate
# ============================================================
section "18. Archives and Unauthorized Tool Sources"
if command -v locate >/dev/null 2>&1; then locate '*.zip' 2>/dev/null | tee "$WORKDIR/zip-files.txt" || true; else find /home /usr/games /opt /usr/local /tmp /var/tmp -type f -iname '*.zip' -print 2>/dev/null | tee "$WORKDIR/zip-files.txt" || true; fi
if [[ -s "$WORKDIR/zip-files.txt" ]]; then
  warn "ZIP archives found. Compare them to required software in README."
  while IFS= read -r f; do
    [[ -f "$f" ]] || continue
    is_protected_path "$f" && continue
    case "$f" in /usr/share/*|/usr/lib/*|/var/lib/*) continue;; esac
    echo "ARCHIVE: $f"; ls -lh "$f" 2>/dev/null || true
    if ask_yes_no "Is this unauthorized and should it be removed?"; then backup_file "$f"; rm -f -- "$f"; fi
  done < "$WORKDIR/zip-files.txt"
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
  netcat netcat-openbsd netcat-traditional ncat pnetcat socat sock socket sbd
  john-data hydra-gtk fcrackzip lcrack ophcrack-cli pdfcrack pyrit rarcrack sipcrack irpas
  inetutils-telnetd telnetd-ssl
  zeitgeist-core zeitgeist-datahub python-zeitgeist rhythmbox-plugin-zeitgeist zeitgeist
)

declare -A SEEN_PKGS=()

echo "Installed packages worth reviewing:"
for p in "${COMMON_REVIEW_PKGS[@]}" $PROHIBITED_PKGS; do
  [[ -z "$p" ]] && continue
  [[ -n "${SEEN_PKGS[$p]+x}" ]] && continue
  SEEN_PKGS["$p"]=1

  if dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q 'install ok installed'; then
    echo "  INSTALLED: $p"
    if contains_line "$p" "$REQUIRED_APPS"; then ok "$p is required; skipping removal."; continue; fi

    if contains_line "$p" "$PROHIBITED_PKGS"; then
      warn "$p was explicitly entered as prohibited."
      ask_yes_no "Purge prohibited package '$p'?" && safe_purge "$p"
    else
      if ask_yes_no "Is '$p' unauthorized on this image and should it be purged?"; then
        safe_purge "$p"
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
# ============================================================
# ADDITIONAL COVERAGE FROM main.sh AND MintScript.sh
# ============================================================
section "Additional: network, repository and startup inspection"
for f in /etc/hosts /etc/resolv.conf /etc/rc.local /etc/apt/sources.list /etc/inetd.conf; do
  echo "--- $f ---"; cat "$f" 2>/dev/null || true
done
grep -RnsE '^[^#].*(deb |URIs:|Suites:|Signed-By:|trusted=yes|AllowUnauthenticated|AllowInsecure)' /etc/apt/sources.list.d /etc/apt/apt.conf.d 2>/dev/null | tee -a "$REPORT" || true
apt-cache policy | tee -a "$REPORT"
find /etc/apt/trusted.gpg.d /etc/apt/keyrings /usr/share/keyrings -maxdepth 1 -type f -print 2>/dev/null || true
command -v nft >/dev/null && nft list ruleset > "$WORKDIR/nft-rules.txt" 2>/dev/null
command -v iptables-save >/dev/null && iptables-save > "$WORKDIR/iptables-rules.txt" 2>/dev/null
command -v ip6tables-save >/dev/null && ip6tables-save > "$WORKDIR/ip6tables-rules.txt" 2>/dev/null
ip address show; ip route show
find /home -mindepth 1 -maxdepth 1 -type d -printf '%u %g %p\n' 2>/dev/null | tee -a "$REPORT"
grep -RnsE 'alias[[:space:]]|/dev/tcp|curl|wget|nc[[:space:]]|socat' /etc/profile /etc/bash.bashrc /etc/profile.d /etc/rc.local /etc/cron.d /etc/crontab /var/spool/cron/crontabs 2>/dev/null | tee -a "$REPORT" || true
grep -RnsE '^Exec(Start|StartPre|StartPost)=.*(python|perl|ruby|php|nc |socat|curl|wget|bash)' /etc/systemd/system 2>/dev/null | tee -a "$REPORT" || true
find /home /root -maxdepth 3 -type f \( -name '.bashrc' -o -name '.profile' -o -name '.bash_history' -o -name 'authorized_keys' \) -print 2>/dev/null | tee "$WORKDIR/user-startup-keys.txt"
while IFS= read -r f; do
  case "$f" in *.bashrc|*.profile) grep -nE 'alias|/dev/tcp|nc |socat|python|curl|wget' "$f" 2>/dev/null | tee -a "$REPORT" || true;; esac
done < "$WORKDIR/user-startup-keys.txt"
warn "Review contents of startup files and keys above. Do not wipe rc.local, histories, hosts, repositories or cron jobs."

section "Additional: critical permissions, ACLs and group passwords"
for f in /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers; do
  stat -c '%a %U:%G %n' "$f" 2>/dev/null | tee -a "$REPORT" || true
done
if [[ $AUDIT_ONLY -eq 0 ]]; then
  for f in /etc/passwd /etc/group; do
    [[ -f "$f" && ! -L "$f" ]] || continue
    run chown root:root "$f"; run chmod 644 "$f"
  done
  for f in /etc/shadow /etc/gshadow; do
    [[ -f "$f" && ! -L "$f" ]] || continue
    if getent group shadow >/dev/null; then run chown root:shadow "$f"; run chmod 640 "$f"; else run chown root:root "$f"; run chmod 600 "$f"; fi
  done
  [[ -f /etc/sudoers && ! -L /etc/sudoers ]] && { run chown root:root /etc/sudoers; run chmod 440 /etc/sudoers; }
fi
for f in /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers /usr/bin/sudo; do
  command -v getfacl >/dev/null && getfacl -p "$f" 2>/dev/null
  command -v lsattr >/dev/null && lsattr "$f" 2>/dev/null
  if [[ $AUDIT_ONLY -eq 0 ]] && command -v getfacl >/dev/null && getfacl -cp "$f" 2>/dev/null | grep -qE '^(user|group):[^:]+'; then
    if ask_yes_no "Remove confirmed unwanted named ACLs from $f?"; then
      getfacl -p "$f" > "$WORKDIR/acl-$(basename "$f").txt"
      backup_file "$f"; run setfacl -b "$f"
    fi
  fi
done
command -v getcap >/dev/null && getcap -r /usr /opt /home 2>/dev/null | tee "$WORKDIR/capabilities.txt"
for g in root sudo adm lpadmin sambashare docker lxd disk shadow; do
  getent group "$g" || continue
  gh="$(getent gshadow "$g" 2>/dev/null | cut -d: -f2)"
  if [[ -n "$gh" && "$gh" != '!'* && "$gh" != '*'* ]]; then
    warn "Usable password on privileged group $g"
    ask_yes_no "Remove the unauthorized group password on $g?" && run gpasswd -r "$g"
  fi
done
warn "Review primary GID 0, sudoers.d, docker/lxd/disk, duplicate UID/GID and package-owned SUID/capability files manually. Locking a UID-0 password does not remove root privileges or SSH keys."
awk -F: '$4==0{print "PRIMARY GID 0:",$1}' /etc/passwd | tee -a "$REPORT"

section "Additional: persistent sysctl policy"
if [[ $AUDIT_ONLY -eq 0 ]]; then
  SYSCTL_FILE=/etc/sysctl.d/99-z-cyberpatriot.conf
  backup_file "$SYSCTL_FILE"
  cat > "$SYSCTL_FILE" <<'SYS'
net.ipv4.tcp_syncookies=1
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv4.icmp_echo_ignore_broadcasts=1
kernel.randomize_va_space=2
kernel.kptr_restrict=2
kernel.dmesg_restrict=1
SYS
  if [[ $ROUTING_REQUIRED -eq 0 ]]; then echo 'net.ipv4.ip_forward=0' >> "$SYSCTL_FILE"; fi
  chmod 644 "$SYSCTL_FILE"
  run sysctl --system
  # sysctl.conf can be loaded later; explicitly check and report overrides.
fi
for k in net.ipv4.tcp_syncookies net.ipv4.ip_forward net.ipv4.conf.all.send_redirects net.ipv4.conf.default.send_redirects net.ipv4.conf.all.accept_redirects net.ipv4.conf.default.accept_redirects net.ipv4.conf.all.secure_redirects net.ipv4.conf.default.secure_redirects net.ipv4.icmp_echo_ignore_broadcasts kernel.randomize_va_space kernel.kptr_restrict kernel.dmesg_restrict; do sysctl "$k" 2>/dev/null || true; done
warn "If runtime values differ, locate later overrides in /etc/sysctl.conf and sysctl.d. Routing remains scenario-dependent."

section "Additional: automatic updates, AppArmor and scanners"
if [[ $AUDIT_ONLY -eq 0 ]] && ask_yes_no "Enable daily update checks and unattended upgrades (README must allow automatic updates)?" Y; then
  run apt-get install -y unattended-upgrades
  CFG=/etc/apt/apt.conf.d/99-cyberpatriot-periodic
  backup_file "$CFG"
  cat > "$CFG" <<'APT'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
APT
  chmod 644 "$CFG"
fi
apt-config dump | grep -E 'APT::Periodic|AllowUnauthenticated|AllowInsecure' || true
if command -v aa-status >/dev/null; then aa-status || true; else warn "AppArmor tools absent"; fi
if ask_yes_no "Install/enable AppArmor and packaged profiles (test required services afterward)?"; then
  run apt-get install -y apparmor apparmor-profiles apparmor-utils
  run systemctl enable --now apparmor
  run aa-status
fi
systemctl is-active auditd 2>/dev/null || true
if ask_yes_no "Install packaged ClamAV, chkrootkit, rkhunter and Lynis for optional scans?"; then
  run apt-get install -y clamav clamav-freshclam chkrootkit rkhunter lynis
fi
warn "Scans are optional manual commands in the guide. No obsolete downloaded Lynis tarball, automatic malware deletion or rkhunter --propupd on an untrusted image."

section "Additional: cron/at access and reboot shortcut"
for f in /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny; do echo "--- $f ---"; cat "$f" 2>/dev/null || true; done
if ask_yes_no "Restrict NEW cron/at submissions to root only (README must permit this)?"; then
  for f in /etc/cron.allow /etc/at.allow; do
    backup_file "$f"; printf 'root\n' > "$f"; run chown root:root "$f"; run chmod 600 "$f"
  done
fi
warn "Allow files do not remove existing jobs; inspect all crontabs. Scheduled services may depend on them."
if ask_yes_no "Disable Ctrl-Alt-Delete reboot on this systemd image?"; then run systemctl mask ctrl-alt-del.target; fi

section "Additional: LightDM/MDM/GDM automatic login"
grep -RnsEi 'allow-guest|autologin|automaticlogin|timedlogin|allowroot' /etc/lightdm /etc/mdm /etc/gdm3 2>/dev/null | tee -a "$REPORT" || true
if ask_yes_no "Disable configured automatic/timed desktop login?"; then
  while IFS= read -r -d '' f; do
    backup_file "$f"
    sed -i -E 's/^([[:space:]]*autologin-user[[:space:]]*=).*/\1/; s/^([[:space:]]*(AutomaticLoginEnable|TimedLoginEnable)[[:space:]]*=).*/\1false/I; s/^([[:space:]]*AllowRoot[[:space:]]*=).*/\1false/I' "$f"
  done < <(find /etc/lightdm /etc/mdm /etc/gdm3 -type f -name '*.conf' -print0 2>/dev/null)
  warn "Changes apply on next login; display manager was not restarted. Verify effective settings."
fi

section "Additional: required applications and service configuration"
for p in $REQUIRED_APPS; do
  if dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q 'install ok installed'; then ok "Required application installed: $p"; else warn "Required application missing: $p"; fi
done
if [[ -f /etc/vsftpd.conf ]] && ask_yes_no "Disable anonymous FTP (only if README forbids anonymous access)?"; then
  set_kv /etc/vsftpd.conf anonymous_enable NO
  warn "vsftpd has no general config-test switch. Review logs and test local login/download after restart."
  run systemctl restart vsftpd
fi
if command -v apache2ctl >/dev/null && ask_yes_no "Set Apache ServerTokens Prod / ServerSignature Off (keep existing sites)?"; then
  APACHE_CFG=/etc/apache2/conf-available/cyberpatriot.conf
  backup_file "$APACHE_CFG"
  printf 'ServerTokens Prod\nServerSignature Off\n' > "$APACHE_CFG"
  chmod 644 "$APACHE_CFG"
  run a2enconf cyberpatriot
  if apache2ctl configtest; then run systemctl reload apache2; else run a2disconf cyberpatriot; warn "Config invalid; snippet disabled."; fi
fi
for d in /etc/mysql /etc/bind /etc/postfix /etc/dovecot /etc/cups /etc/samba /etc/nginx /etc/apache2 /etc/vsftpd /etc/xinetd.d; do
  [[ -d "$d" ]] || continue
  echo "--- configuration review: $d ---"
  find "$d" -maxdepth 2 -type f -print 2>/dev/null
 done
warn "Guide covers Samba credentials/shares, FTP chroot, Apache directory listing, DNS, mail, database and print service checks. Avoid generic config replacement."

section "Additional: comprehensive media and tool-file inventory"
# Exact extension coverage from both supplied scripts, plus modern formats. Inventory only.
MEDIA_EXTS='midi mid mod mp3 mp2 mpa abs mpega au snd wav aiff aif sid flac ogg m4a aac opus mpeg mpg mpe dl movie movi mv iff anim5 anim3 anim7 avi vfw avx fli flc mov qt spl swf dcr dir dxr rpm rm smi ra ram rv wmv asf asx wma wax wmx 3gp mp4 flv m4v mkv webm tiff tif rs im1 gif jpeg jpg jpe png rgb xwd xpm ppm pbm pgm pcx ico svg svgz bmp webp heic'
while IFS= read -r -d '' f; do
  is_protected_path "$f" && continue
  ext="${f##*.}"; ext="${ext,,}"
  case " $MEDIA_EXTS " in *" $ext "*) printf '%s\n' "$f" >> "$WORKDIR/media-review.txt";; esac
  if contains_line "$ext" "$PROHIBITED_EXTS"; then
    printf '%s\n' "$f" >> "$WORKDIR/prohibited-extension-review.txt"
    if ask_yes_no "README prohibits .$ext: delete this verified non-evidence file '$f'?"; then backup_file "$f"; rm -f -- "$f"; fi
  fi
done < <(find /home /root /srv /var/www /usr/games /opt /usr/local /tmp /var/tmp -type f -print0 2>/dev/null)
warn "Media inventory: $WORKDIR/media-review.txt (if matches). Content/signature checks and separate mounted filesystems remain manual. .rpm/.svg/.ico/.wav and other matches can be legitimate."
find /usr/local/bin /usr/games /opt /home -type f \( -iname '*netcat*' -o -iname '*hydra*' -o -iname '*john*' -o -iname '*crack*' -o -iname '*.AppImage' -o -iname '*.sh' \) -print 2>/dev/null | tee "$WORKDIR/tool-files-review.txt"


# pam-auth-update may regenerate files; reapply recurring null-password protection.
if [[ $AUDIT_ONLY -eq 0 && -f /etc/pam.d/common-auth ]]; then
  sed -ri '/pam_unix\.so/ s/[[:space:]]+nullok(_secure)?\>//g' /etc/pam.d/common-auth
fi
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
echo "--- PAM password policy ---"
grep -nE '^[[:space:]]*password.*pam_(unix|pwquality|pwhistory)\.so' /etc/pam.d/common-password 2>/dev/null || true

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
# 28. CP-STYLE READINESS VERIFICATION
# ============================================================
section "28. CP-Style Readiness Verification"
FAILS=0
if [[ -z "$(getent shadow root | cut -d: -f2)" ]]; then warn "FAIL: root password blank"; ((FAILS+=1)); else ok "Root password not blank"; fi
if grep -E '^[[:space:]]*password.*pam_pwquality\.so' /etc/pam.d/common-password 2>/dev/null | grep -q "minlen=$PW_MINLEN"; then ok "Quality profile present (verify with a password change)"; else warn "FAIL: active password quality not verified"; ((FAILS+=1)); fi
if grep -q 'pam_faillock\.so.*preauth' /etc/pam.d/common-auth 2>/dev/null && grep -q 'pam_faillock\.so.*authfail' /etc/pam.d/common-auth 2>/dev/null && grep -q 'pam_faillock\.so.*authsucc' /etc/pam.d/common-auth 2>/dev/null; then ok "pam_faillock complete"; else warn "FAIL: pam_faillock incomplete"; ((FAILS+=1)); fi
if grep -E '^[[:space:]]*auth.*pam_unix\.so' /etc/pam.d/common-auth 2>/dev/null | grep -qE '(^|[[:space:]])nullok(_secure)?([[:space:]]|$)'; then warn "FAIL: nullok remains"; ((FAILS+=1)); else ok "nullok absent"; fi
if [[ "$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null || echo 0)" == 1 ]]; then ok "SYN cookies enabled"; else warn "FAIL: SYN cookies disabled"; ((FAILS+=1)); fi
if ufw status 2>/dev/null | grep -q '^Status: active'; then ok "UFW active"; else warn "FAIL: UFW inactive"; ((FAILS+=1)); fi
if ss -ltnp 2>/dev/null | grep -qE 'users:\(\("python[0-9]*"'; then warn "REVIEW: Python TCP listener remains; may be legitimate"; else ok "No obvious Python TCP listener"; fi
for svc in $REQUIRED_SERVICES; do [[ -z "$svc" ]] && continue; systemctl is-active --quiet "$svc" || { warn "FAIL: required service $svc inactive"; ((FAILS+=1)); }; done
echo; if (( FAILS==0 )); then ok "All v5 readiness checks passed."; else warn "$FAILS readiness check(s) still need attention."; fi

# ============================================================
# 29. MANUAL CHECKLIST
# ============================================================
section "29. Manual Checks Still Required"

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
