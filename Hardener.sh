#!/usr/bin/env bash
# CyberPatriot Linux Interactive Hardening Assistant
# Target: Ubuntu / Linux Mint / Debian-family competition images
#
# Usage:
#   sudo bash CyberPatriot_Linux_Hardener.sh
#   sudo bash CyberPatriot_Linux_Hardener.sh --audit
#
# IMPORTANT:
# - Read the image ReadMe FIRST.
# - This script asks before destructive/service-impacting changes.
# - Do not interfere with CyberPatriot scoring components.

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
  RESET=$'\033[0m'
else
  BOLD=""; RED=""; GREEN=""; YELLOW=""; BLUE=""; RESET=""
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

if [[ $EUID -ne 0 ]]; then
  err "Run as root: sudo bash $0"
  exit 1
fi

if ! command -v apt >/dev/null 2>&1; then
  err "Designed for Ubuntu/Linux Mint/Debian systems using apt."
  exit 1
fi

echo
echo "${BOLD}CyberPatriot Linux Interactive Hardening Assistant${RESET}"
echo "Work directory: $WORKDIR"
warn "READ THE IMAGE README BEFORE MAKING CHANGES."
warn "Required services and authorized users differ between images."
warn "Do not modify CyberPatriot scoring components."
[[ $AUDIT_ONLY -eq 1 ]] && warn "AUDIT MODE: configuration-changing prompts will be skipped."

section "System Information"
if [[ -r /etc/os-release ]]; then
  . /etc/os-release
  DISTRO="${PRETTY_NAME:-unknown}"
else
  DISTRO="unknown"
fi
log "Distribution: $DISTRO"
log "Hostname: $(hostname)"
log "Kernel: $(uname -r)"

section "Scenario Inputs"
echo "Enter information exactly from the image ReadMe."
echo "Separate multiple entries with spaces or commas."
echo
read -r -p "Authorized standard users: " AUTH_USERS_RAW
read -r -p "Authorized administrators: " AUTH_ADMINS_RAW
read -r -p "Required services (e.g. ssh apache2 samba): " REQUIRED_SERVICES_RAW
read -r -p "Required incoming ports (e.g. 22/tcp 80/tcp 53/udp): " REQUIRED_PORTS_RAW

AUTH_USERS="$(parse_list "$AUTH_USERS_RAW")"
AUTH_ADMINS="$(parse_list "$AUTH_ADMINS_RAW")"
REQUIRED_SERVICES="$(parse_list "$REQUIRED_SERVICES_RAW")"
REQUIRED_PORTS="$(parse_list "$REQUIRED_PORTS_RAW")"
ALL_AUTHORIZED="$(printf '%s\n%s\n' "$AUTH_USERS" "$AUTH_ADMINS" | sed '/^$/d' | sort -u)"

PASS_MAX_DAYS=90
PASS_MIN_DAYS=1
PASS_WARN_AGE=7
PW_MINLEN=12

if [[ $AUDIT_ONLY -eq 0 ]]; then
  read -r -p "Password max age [$PASS_MAX_DAYS]: " tmp; PASS_MAX_DAYS="${tmp:-$PASS_MAX_DAYS}"
  read -r -p "Password min age [$PASS_MIN_DAYS]: " tmp; PASS_MIN_DAYS="${tmp:-$PASS_MIN_DAYS}"
  read -r -p "Password warning days [$PASS_WARN_AGE]: " tmp; PASS_WARN_AGE="${tmp:-$PASS_WARN_AGE}"
  read -r -p "Minimum password length [$PW_MINLEN]: " tmp; PW_MINLEN="${tmp:-$PW_MINLEN}"
fi

section "Baseline Snapshot"
{
  echo "Date: $(date -Is)"
  echo "--- passwd ---"; cat /etc/passwd
  echo "--- sudo ---"; getent group sudo 2>/dev/null || true
  echo "--- listening sockets ---"; ss -tulpn 2>/dev/null || true
  echo "--- running services ---"; systemctl --type=service --state=running --no-pager 2>/dev/null || true
  echo "--- enabled services ---"; systemctl list-unit-files --type=service --state=enabled --no-pager 2>/dev/null || true
  echo "--- firewall ---"; ufw status verbose 2>/dev/null || true
} > "$WORKDIR/baseline.txt"
ok "Saved baseline to $WORKDIR/baseline.txt"

section "Users and Administrators"
HUMAN_USERS="$(awk -F: '($3 >= 1000 && $1 != "nobody"){print $1}' /etc/passwd | sort -u)"
echo "Human accounts:"
printf '  %s\n' $HUMAN_USERS 2>/dev/null || true
echo
echo "Current sudo group:"
getent group sudo || true

if [[ -n "$ALL_AUTHORIZED" ]]; then
  for u in $HUMAN_USERS; do
    [[ -z "$u" ]] && continue
    if ! contains_line "$u" "$ALL_AUTHORIZED"; then
      warn "Potential unauthorized account: $u"
      if ask_yes_no "Delete '$u' and its home directory?"; then
        run userdel -r "$u" || warn "Could not fully delete $u."
      elif ask_yes_no "Lock '$u' instead?"; then
        run usermod -L "$u"
      fi
    fi
  done
fi

for u in $AUTH_ADMINS; do
  [[ -z "$u" ]] && continue
  if ! id "$u" >/dev/null 2>&1; then
    warn "Authorized administrator '$u' does not exist."
    ask_yes_no "Create '$u'?" && adduser "$u"
  fi
  if id "$u" >/dev/null 2>&1 && ! id -nG "$u" | tr ' ' '\n' | grep -Fxq sudo; then
    warn "$u should be admin but is not in sudo."
    ask_yes_no "Add '$u' to sudo?" && run usermod -aG sudo "$u"
  fi
done

for u in $AUTH_USERS; do
  [[ -z "$u" ]] && continue
  if ! id "$u" >/dev/null 2>&1; then
    warn "Authorized user '$u' does not exist."
    ask_yes_no "Create '$u'?" && adduser "$u"
  fi
  if id "$u" >/dev/null 2>&1 && id -nG "$u" | tr ' ' '\n' | grep -Fxq sudo; then
    warn "$u is a standard user but has sudo."
    ask_yes_no "Remove '$u' from sudo?" && run gpasswd -d "$u" sudo
  fi
done

echo
echo "Privileged groups:"
for g in sudo adm root docker lxd libvirt disk shadow; do
  getent group "$g" 2>/dev/null || true
done

UID0_USERS="$(awk -F: '$3 == 0 {print $1}' /etc/passwd)"
echo "UID 0 accounts: $UID0_USERS"
for u in $UID0_USERS; do
  if [[ "$u" != root ]]; then
    warn "NON-ROOT UID 0 ACCOUNT: $u"
    ask_yes_no "Lock '$u'?" && run usermod -L "$u"
  fi
done

EMPTY_PASS_USERS="$(awk -F: '($2 == "") {print $1}' /etc/shadow 2>/dev/null || true)"
[[ -n "$EMPTY_PASS_USERS" ]] && warn "Empty password accounts: $EMPTY_PASS_USERS"

section "Password Aging and Quality"
grep -E '^[[:space:]]*PASS_(MAX|MIN|WARN)_DAYS' /etc/login.defs 2>/dev/null || true

if ask_yes_no "Set login.defs aging to MAX=$PASS_MAX_DAYS MIN=$PASS_MIN_DAYS WARN=$PASS_WARN_AGE?"; then
  backup_file /etc/login.defs
  sed -ri "s/^[#[:space:]]*PASS_MAX_DAYS[[:space:]]+.*/PASS_MAX_DAYS   $PASS_MAX_DAYS/" /etc/login.defs
  sed -ri "s/^[#[:space:]]*PASS_MIN_DAYS[[:space:]]+.*/PASS_MIN_DAYS   $PASS_MIN_DAYS/" /etc/login.defs
  sed -ri "s/^[#[:space:]]*PASS_WARN_AGE[[:space:]]+.*/PASS_WARN_AGE   $PASS_WARN_AGE/" /etc/login.defs
fi

for u in $ALL_AUTHORIZED; do
  [[ -z "$u" ]] && continue
  id "$u" >/dev/null 2>&1 || continue
  chage -l "$u" 2>/dev/null || true
  if ask_yes_no "Apply password aging policy to '$u'?"; then
    run chage -M "$PASS_MAX_DAYS" -m "$PASS_MIN_DAYS" -W "$PASS_WARN_AGE" "$u"
  fi
done

if dpkg-query -W -f='${Status}' libpam-pwquality 2>/dev/null | grep -q "install ok installed"; then
  ok "libpam-pwquality installed."
else
  warn "libpam-pwquality not installed."
  if ask_yes_no "Install libpam-pwquality?"; then
    run apt-get update
    run apt-get install -y libpam-pwquality
  fi
fi

if [[ -d /etc/security/pwquality.conf.d || -f /etc/security/pwquality.conf ]]; then
  if ask_yes_no "Create pwquality policy (minlen=$PW_MINLEN, minclass=3, difok=4)?"; then
    mkdir -p /etc/security/pwquality.conf.d
    POLICY="/etc/security/pwquality.conf.d/99-cyberpatriot.conf"
    backup_file "$POLICY"
    cat > "$POLICY" <<EOF
minlen = $PW_MINLEN
minclass = 3
difok = 4
retry = 3
EOF
    chmod 644 "$POLICY"
  fi
fi
warn "PAM password-history edits are left manual because a bad PAM change can lock out all users."

section "Updates"
apt list --upgradable 2>/dev/null || true
if ask_yes_no "Run apt update and apt upgrade?"; then
  run apt-get update
  run env DEBIAN_FRONTEND=noninteractive apt-get upgrade -y
fi

section "Installed Packages to Review"
for p in telnet telnetd rsh-client rsh-server rsh-redone-client rsh-redone-server talk talkd tftpd-hpa vsftpd ftp netcat-traditional john ophcrack hydra nikto; do
  if dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q "install ok installed"; then
    echo "INSTALLED: $p"
  fi
done
warn "Do not remove packages blindly. Check the ReadMe and required services first."

section "Firewall"
if command -v ufw >/dev/null 2>&1; then
  run ufw status verbose || true
  if ask_yes_no "Apply default deny incoming / allow outgoing and enable UFW?"; then
    run ufw default deny incoming
    run ufw default allow outgoing
    for p in $REQUIRED_PORTS; do
      [[ -n "$p" ]] && run ufw allow "$p"
    done
    run ufw --force enable
    run ufw status numbered
  fi
else
  warn "UFW is not installed."
  if ask_yes_no "Install UFW?"; then
    run apt-get update
    run apt-get install -y ufw
  fi
fi

section "Listening Ports"
ss -tulpn 2>/dev/null | tee -a "$REPORT" || true
warn "Every listening port should correspond to a required or understood service."

section "Services"
systemctl --type=service --state=running --no-pager 2>/dev/null | tee -a "$REPORT" || true
echo
systemctl list-unit-files --type=service --state=enabled --no-pager 2>/dev/null | tee -a "$REPORT" || true

REVIEW_SERVICES=(
  telnet.socket telnet.service xinetd.service rsh.socket rlogin.socket rexec.socket
  tftpd-hpa.service vsftpd.service proftpd.service pure-ftpd.service
  apache2.service nginx.service smbd.service nmbd.service cups.service
  avahi-daemon.service rpcbind.service nfs-server.service ssh.service
)

for svc in "${REVIEW_SERVICES[@]}"; do
  if systemctl list-unit-files "$svc" --no-legend 2>/dev/null | grep -q .; then
    state="$(systemctl is-enabled "$svc" 2>/dev/null || true)"
    active="$(systemctl is-active "$svc" 2>/dev/null || true)"
    printf '%-24s enabled=%-12s active=%s\n' "$svc" "$state" "$active"
    base="${svc%.service}"; base="${base%.socket}"
    if ! contains_line "$svc" "$REQUIRED_SERVICES" && ! contains_line "$base" "$REQUIRED_SERVICES"; then
      if [[ "$active" == active || "$state" == enabled ]]; then
        ask_yes_no "Disable '$svc'?" && run systemctl disable --now "$svc"
      fi
    fi
  fi
done

section "SSH"
if command -v sshd >/dev/null 2>&1 || dpkg-query -W openssh-server >/dev/null 2>&1; then
  sshd -T 2>/dev/null | grep -Ei '^(permitrootlogin|permitemptypasswords|maxauthtries|x11forwarding|passwordauthentication|pubkeyauthentication)\b' || true
  if ask_yes_no "Install safe SSH hardening drop-in?"; then
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
      ok "SSH config valid."
      systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
    else
      err "SSH config invalid. Removing new drop-in."
      rm -f "$DROPIN"
    fi
  fi
else
  echo "OpenSSH server not installed."
fi
warn "PasswordAuthentication is intentionally left unchanged because some scenarios require it."

section "Sudoers"
grep -RhnE '^[[:space:]]*[^#].*(ALL|NOPASSWD)' /etc/sudoers /etc/sudoers.d 2>/dev/null | tee -a "$REPORT" || true
if command -v visudo >/dev/null 2>&1; then
  visudo -c || warn "sudoers has a syntax problem."
fi

section "Cron, Timers, and Persistence"
cat /etc/crontab 2>/dev/null || true
find /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly \
  -maxdepth 1 -type f -print 2>/dev/null | sort || true

for u in $(cut -d: -f1 /etc/passwd); do
  cron="$(crontab -u "$u" -l 2>/dev/null || true)"
  if [[ -n "$cron" ]]; then
    echo "[$u]"
    printf '%s\n' "$cron"
  fi
done

systemctl list-timers --all --no-pager 2>/dev/null || true
find /etc/systemd/system -type f \( -name '*.service' -o -name '*.timer' \) -print 2>/dev/null | sort || true
warn "Inspect suspicious cron jobs/timers manually. Do not bulk-delete them."

section "Processes"
echo "Root processes:"
ps -U root -u root u 2>/dev/null | tee -a "$REPORT" || true
echo
echo "Highest CPU:"
ps aux --sort=-%cpu 2>/dev/null | head -n 20 | tee -a "$REPORT" || true
echo
echo "Deleted executables:"
find /proc/[0-9]*/exe -lname '* (deleted)' -printf '%p -> %l\n' 2>/dev/null | tee -a "$REPORT" || true

section "File Permissions"
echo "World-writable regular files:"
find / -xdev -type f -perm -0002 -print 2>/dev/null | tee -a "$REPORT" || true
echo
echo "World-writable dirs without sticky bit:"
find / -xdev -type d -perm -0002 ! -perm -1000 -print 2>/dev/null | tee -a "$REPORT" || true
echo
echo "SUID:"
find / -xdev -type f -perm -4000 -print 2>/dev/null | tee -a "$REPORT" || true
echo
echo "SGID:"
find / -xdev -type f -perm -2000 -print 2>/dev/null | tee -a "$REPORT" || true
echo
stat -c '%a %U:%G %n' /etc/passwd /etc/shadow /etc/group /etc/gshadow 2>/dev/null | tee -a "$REPORT" || true
warn "Investigate unusual permission results instead of mass-changing them."

section "Media / Prohibited Files"
if ask_yes_no "Does the ReadMe prohibit music/video files?"; then
  find /home -type f \( \
    -iname '*.mp3' -o -iname '*.wav' -o -iname '*.flac' -o -iname '*.ogg' -o \
    -iname '*.mp4' -o -iname '*.mkv' -o -iname '*.avi' -o -iname '*.mov' -o \
    -iname '*.wmv' -o -iname '*.m4a' \
  \) -print 2>/dev/null | tee "$WORKDIR/media-files.txt"
  warn "Review files before deleting them."
fi

echo
echo "Scripts/executables in home directories:"
find /home -type f \( -name '*.sh' -o -name '*.py' -o -name '*.pl' -o -name '*.php' -o -perm /111 \) \
  -print 2>/dev/null | head -n 500 | tee -a "$REPORT" || true

section "Authentication / Login"
echo "Login-capable accounts:"
awk -F: '$7 !~ /(nologin|false)$/ {print $1 ":" $3 ":" $7}' /etc/passwd
echo
passwd -S root 2>/dev/null || true
echo
last -a 2>/dev/null | head -n 30 || true
echo
lastb -a 2>/dev/null | head -n 30 || true

if dpkg-query -W lightdm >/dev/null 2>&1; then
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

section "Network Kernel Settings"
SYSCTL_KEYS=(
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
for k in "${SYSCTL_KEYS[@]}"; do sysctl "$k" 2>/dev/null || true; done

if ask_yes_no "Apply conservative network hardening sysctls?"; then
  SYSCTL_FILE="/etc/sysctl.d/99-cyberpatriot-hardening.conf"
  backup_file "$SYSCTL_FILE"
  cat > "$SYSCTL_FILE" <<'EOF'
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
warn "If the ReadMe says the machine is a router, do NOT disable IP forwarding."

section "Logs"
if [[ -f /var/log/auth.log ]]; then
  tail -n 100 /var/log/auth.log
else
  journalctl -n 100 --no-pager 2>/dev/null || true
fi
echo
systemctl --failed --no-pager 2>/dev/null || true

section "Required Service Checks"
for svc in $REQUIRED_SERVICES; do
  [[ -n "$svc" ]] || continue
  echo "### $svc"
  systemctl status "$svc" --no-pager 2>/dev/null | head -n 25 || true
done

if systemctl list-unit-files apache2.service --no-legend 2>/dev/null | grep -q .; then
  echo "Apache modules:"
  apache2ctl -M 2>/dev/null || true
  grep -RniE 'Indexes|ServerTokens|ServerSignature' /etc/apache2 2>/dev/null || true
fi

if command -v testparm >/dev/null 2>&1; then
  echo "Samba config:"
  testparm -s 2>/dev/null || true
fi

if [[ -f /etc/vsftpd.conf ]]; then
  grep -Ei '^(anonymous_enable|local_enable|write_enable|chroot_local_user|allow_writeable_chroot)' \
    /etc/vsftpd.conf 2>/dev/null || true
fi

section "Final Verification"
echo "--- Users ---"
awk -F: '($3 >= 1000 && $1 != "nobody"){print $1,$3,$7}' /etc/passwd
echo
echo "--- Sudo ---"
getent group sudo || true
echo
echo "--- Listening ports ---"
ss -tulpn 2>/dev/null || true
echo
echo "--- Firewall ---"
ufw status verbose 2>/dev/null || true
echo
echo "--- Failed units ---"
systemctl --failed --no-pager 2>/dev/null || true

if command -v sshd >/dev/null 2>&1; then
  sshd -t && ok "sshd config valid." || err "sshd config INVALID."
fi

if command -v visudo >/dev/null 2>&1; then
  visudo -c >/dev/null 2>&1 && ok "sudoers config valid." || err "sudoers config INVALID."
fi

for svc in $REQUIRED_SERVICES; do
  [[ -n "$svc" ]] || continue
  if systemctl is-active --quiet "$svc" 2>/dev/null; then
    ok "Required service active: $svc"
  else
    warn "Required service NOT active: $svc"
  fi
done

section "Manual Checks Still Required"
cat <<'EOF'
[ ] Answer forensic questions using evidence.
[ ] Re-read the ReadMe.
[ ] Compare all users/admins against the ReadMe.
[ ] Review every listening port.
[ ] Review suspicious cron jobs and timers.
[ ] Review unusual SUID/SGID binaries.
[ ] Review world-writable files/directories.
[ ] Review suspicious/hacking/P2P software.
[ ] Review browser settings/extensions if relevant.
[ ] Review required server configs.
[ ] Review PAM/password history manually.
[ ] Check autologin/guest login.
[ ] Check /tmp, /var/tmp, /usr/local, /opt and startup files.
[ ] Verify required services still work.
[ ] Watch the CyberPatriot score after changes.
EOF

echo
echo "${GREEN}${BOLD}Finished.${RESET}"
echo "Log:     $LOG"
echo "Report:  $REPORT"
echo "Backups: $BACKUP_DIR"
