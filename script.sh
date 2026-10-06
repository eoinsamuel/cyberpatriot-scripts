#!/usr/bin/env bash
#
# CyberPatriot Linux Security Audit Script
# Distribution: Ubuntu / Debian / Linux Mint
# Mode: Inspect + Report (no changes made to the system)
#
# Usage:
#   sudo bash cp-audit.sh
#
# Output:
#   - On-screen summary during run
#   - Full report saved to ~/cp-audit-report-YYYYMMDD-HHMMSS.txt
#
# ============================================================

set -o pipefail

# ---------- Setup ----------

REPORT_DIR="$HOME"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
REPORT_FILE="${REPORT_DIR}/cp-audit-report-${TIMESTAMP}.txt"

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'  # No Color

# ---------- Helper Functions ----------

# Write a line to both terminal and report file
log() {
    echo -e "$1" | tee -a "$REPORT_FILE"
}

# Write a section header
header() {
    echo "" | tee -a "$REPORT_FILE"
    echo "==============================================================" | tee -a "$REPORT_FILE"
    echo "  $1" | tee -a "$REPORT_FILE"
    echo "==============================================================" | tee -a "$REPORT_FILE"
}

# Write a sub-header
subheader() {
    echo "" | tee -a "$REPORT_FILE"
    echo "--- $1 ---" | tee -a "$REPORT_FILE"
}

# Run a command and capture output, with a label
run_check() {
    local label="$1"
    shift
    echo "" | tee -a "$REPORT_FILE"
    echo ">>> $label" | tee -a "$REPORT_FILE"
    echo "    Command: $*" | tee -a "$REPORT_FILE"
    echo "" | tee -a "$REPORT_FILE"
    "$@" 2>&1 | tee -a "$REPORT_FILE"
    echo "" | tee -a "$REPORT_FILE"
}

# Run a command in a subshell and capture output
run_cmd() {
    local label="$1"
    local cmd="$2"
    echo "" | tee -a "$REPORT_FILE"
    echo ">>> $label" | tee -a "$REPORT_FILE"
    echo "    Command: $cmd" | tee -a "$REPORT_FILE"
    echo "" | tee -a "$REPORT_FILE"
    eval "$cmd" 2>&1 | tee -a "$REPORT_FILE"
    echo "" | tee -a "$REPORT_FILE"
}

# ---------- Root Check ----------

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}${BOLD}This script must be run as root.${NC}"
    echo "Run with: sudo bash cp-audit.sh"
    exit 1
fi

# ---------- Initialize Report ----------

echo "CyberPatriot Linux Security Audit Report" > "$REPORT_FILE"
echo "Date: $(date)" >> "$REPORT_FILE"
echo "Host: $(hostname)" >> "$REPORT_FILE"
echo "User: $(whoami)" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# ---------- Interactive README Input ----------

header "README / SCENARIO INPUT"

echo -e "${CYAN}Enter the details from the README. Press Enter to skip any field.${NC}"
echo ""

# Authorized users
read -p "Authorized users (space-separated usernames): " AUTH_USERS
read -p "Authorized administrators (space-separated): " AUTH_ADMINS
read -p "Required services (space-separated, e.g. ssh apache2): " REQ_SERVICES
read -p "Prohibited software/packages (space-separated): " PROHIBITED_PKG
read -p "Prohibited files/directories (space-separated paths): " PROHIBITED_FILES

echo ""
echo -e "${YELLOW}Recording scenario details...${NC}"

log "SCENARIO DETAILS:"
log "  Authorized users:    ${AUTH_USERS:-<none specified>}"
log "  Authorized admins:   ${AUTH_ADMINS:-<none specified>}"
log "  Required services:   ${REQ_SERVICES:-<none specified>}"
log "  Prohibited packages: ${PROHIBITED_PKG:-<none specified>}"
log "  Prohibited files:    ${PROHIBITED_FILES:-<none specified>}"

# ---------- Start Audit ----------

echo ""
echo -e "${GREEN}${BOLD}Starting system audit...${NC}"
echo -e "${YELLOW}Report will be saved to: ${REPORT_FILE}${NC}"
echo ""

# ============================================================
# 1. SYSTEM INFORMATION
# ============================================================

header "1. SYSTEM INFORMATION"

run_cmd "OS Release" "cat /etc/os-release"
run_cmd "Kernel" "uname -a"
run_cmd "Hostname" "hostname"
run_cmd "Uptime" "uptime"
run_cmd "Disk Usage" "df -h"
run_cmd "Memory" "free -h"
run_cmd "CPU Info" "lscpu | head -20"

# ============================================================
# 2. USER & GROUP AUDIT
# ============================================================

header "2. USER & GROUP AUDIT"

subheader "All User Accounts"
run_cmd "All users (getent passwd)" "getent passwd"
run_cmd "Human accounts (UID >= 1000)" "awk -F: '\$3 >= 1000 && \$3 < 65534 {print \$1, \$3, \$6, \$7}' /etc/passwd"
run_cmd "Accounts with UID 0 (should be root only)" "awk -F: '\$3 == 0 {print \$1}' /etc/passwd"
run_cmd "Duplicate UIDs" "awk -F: '{print \$3}' /etc/passwd | sort | uniq -d"
run_cmd "Users with login shells" "grep -v '/nologin\|/false' /etc/passwd"
run_cmd "Users with no password / empty password" "awk -F: '(\$2 == \"\" || \$2 == \"*\") {print \$1}' /etc/shadow"
run_cmd "Password status for all users" "for u in \$(awk -F: '\$3 >= 1000 && \$3 < 65534 {print \$1}' /etc/passwd); do echo -n \"\$u: \"; passwd -S \$u 2>/dev/null; done"

# Compare against authorized users
if [[ -n "$AUTH_USERS" ]]; then
    subheader "Authorized User Comparison"
    log "Authorized users from README: $AUTH_USERS"
    log ""
    log "Users on system NOT in authorized list:"
    for u in $(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd); do
        if ! echo "$AUTH_USERS" | grep -qw "$u"; then
            log "  [!] UNAUTHORIZED: $u"
        fi
    done
    log ""
    log "Authorized users NOT found on system:"
    for u in $AUTH_USERS; do
        if ! getent passwd "$u" >/dev/null 2>&1; then
            log "  [!] MISSING: $u"
        fi
    done
fi

subheader "Groups & Administrative Access"
run_cmd "All groups" "getent group"
run_cmd "sudo group members" "getent group sudo"
run_cmd "admin group members" "getent group admin 2>/dev/null || echo 'admin group not found'"
run_cmd "wheel group members" "getent group wheel 2>/dev/null || echo 'wheel group not found'"
run_cmd "Members of adm group" "getent group adm"
run_cmd "Members of lpadmin group" "getent group lpadmin 2>/dev/null || echo 'lpadmin group not found'"
run_cmd "Members of docker group" "getent group docker 2>/dev/null || echo 'docker group not found'"

# Compare admins against authorized list
if [[ -n "$AUTH_ADMINS" ]]; then
    subheader "Authorized Admin Comparison"
    log "Authorized admins from README: $AUTH_ADMINS"
    log ""
    log "Admins on system NOT in authorized list:"
    for u in $(getent group sudo | cut -d: -f4 | tr ',' '\n' | sed 's/^ *//;s/ *$//'); do
        if [[ -n "$u" ]] && ! echo "$AUTH_ADMINS" | grep -qw "$u"; then
            log "  [!] UNAUTHORIZED ADMIN (sudo): $u"
        fi
    done
    for u in $(getent group admin 2>/dev/null | cut -d: -f4 | tr ',' '\n' | sed 's/^ *//;s/ *$//'); do
        if [[ -n "$u" ]] && ! echo "$AUTH_ADMINS" | grep -qw "$u"; then
            log "  [!] UNAUTHORIZED ADMIN (admin): $u"
        fi
    done
    log ""
    log "Authorized admins NOT in sudo/admin group:"
    for u in $AUTH_ADMINS; do
        if ! getent group sudo | grep -qw "$u" 2>/dev/null; then
            log "  [!] NOT ADMIN: $u"
        fi
    done
fi

subheader "Password Aging"
run_cmd "Global password policy (login.defs)" "grep -E 'PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE' /etc/login.defs"
for u in $(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd); do
    run_cmd "Password aging for $u" "chage -l $u"
done

# ============================================================
# 3. SUDO CONFIGURATION
# ============================================================

header "3. SUDO CONFIGURATION"

run_cmd "Main sudoers file" "cat /etc/sudoers"
run_cmd "sudoers.d directory listing" "ls -la /etc/sudoers.d/"
run_cmd "Contents of sudoers.d files" "for f in /etc/sudoers.d/*; do echo \"=== \$f ===\"; cat \"\$f\" 2>/dev/null; echo; done"
run_cmd "Sudoers syntax validation" "visudo -c"
run_cmd "All NOPASSWD entries (security risk)" "grep -rn 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null || echo 'No NOPASSWD entries found'"
run_cmd "All sudo privilege grants" "grep -rn 'ALL=(ALL\|ALL=(root' /etc/sudoers /etc/sudoers.d/ 2>/dev/null || echo 'None found'"

# ============================================================
# 4. SERVICES & PORTS
# ============================================================

header "4. SERVICES & PORTS"

subheader "Running Services"
run_cmd "Running services" "systemctl --type=service --state=running --no-pager"
run_cmd "Enabled services (start at boot)" "systemctl list-unit-files --type=service --state=enabled --no-pager"
run_cmd "All service states" "systemctl list-unit-files --type=service --no-pager"

subheader "Listening Ports"
run_cmd "All listening ports with processes" "ss -tulpn"
run_cmd "All active connections" "ss -tuna"
run_cmd "netstat fallback (if ss unavailable)" "netstat -tulpn 2>/dev/null || echo 'netstat not available'"

subheader "Common Unnecessary Services Check"
for svc in apache2 nginx vsftpd proftpd telnet rsh rlogin samba smbd nmbd nfs-common rpcbind snmpd cups avahi-daemon bluetooth postfix dovecot slapd squid dansguardian; do
    status=$(systemctl is-enabled "$svc" 2>/dev/null)
    active=$(systemctl is-active "$svc" 2>/dev/null)
    if [[ "$status" != "disabled" && "$status" != "not-found" && "$status" != "unknown" ]]; then
        log "  [!] $svc — enabled: $status, active: $active"
    fi
done

# Check required services are running
if [[ -n "$REQ_SERVICES" ]]; then
    subheader "Required Services Check"
    for svc in $REQ_SERVICES; do
        status=$(systemctl is-active "$svc" 2>/dev/null)
        enabled=$(systemctl is-enabled "$svc" 2>/dev/null)
        log "  $svc — active: $status, enabled: $enabled"
        if [[ "$status" != "active" ]]; then
            log "  [!] REQUIRED SERVICE NOT RUNNING: $svc"
        fi
    done
fi

# ============================================================
# 5. FIREWALL STATUS
# ============================================================

header "5. FIREWALL STATUS"

run_cmd "UFW status" "ufw status verbose 2>/dev/null || echo 'UFW not available'"
run_cmd "UFW is enabled?" "ufw status 2>/dev/null | head -1"
run_cmd "iptables rules" "iptables -L -n -v"
run_cmd "iptables NAT rules" "iptables -t nat -L -n -v"
run_cmd "ip6tables rules" "ip6tables -L -n -v 2>/dev/null || echo 'ip6tables not available'"

# ============================================================
# 6. SSH CONFIGURATION
# ============================================================

header "6. SSH CONFIGURATION"

run_cmd "SSH server installed?" "dpkg -l | grep openssh-server || echo 'openssh-server not installed'"
run_cmd "SSH service status" "systemctl status ssh 2>/dev/null || systemctl status sshd 2>/dev/null || echo 'SSH service not found'"
run_cmd "SSH config file" "cat /etc/ssh/sshd_config 2>/dev/null || echo 'sshd_config not found'"
run_cmd "SSH drop-in config files" "ls -la /etc/ssh/sshd_config.d/ 2>/dev/null && for f in /etc/ssh/sshd_config.d/*.conf; do echo \"=== \$f ===\"; cat \"\$f\" 2>/dev/null; echo; done || echo 'No drop-in configs'"
run_cmd "SSH config validation" "/usr/sbin/sshd -t 2>&1 || echo 'SSH config validation failed or sshd not installed'"
run_cmd "Effective SSH settings" "/usr/sbin/sshd -T 2>/dev/null || echo 'Could not retrieve effective SSH settings'"

subheader "Key SSH Security Settings"
run_cmd "PermitRootLogin" "/usr/sbin/sshd -T 2>/dev/null | grep -i permitrootlogin || echo 'Could not check'"
run_cmd "PermitEmptyPasswords" "/usr/sbin/sshd -T 2>/dev/null | grep -i permitemptypasswords || echo 'Could not check'"
run_cmd "PasswordAuthentication" "/usr/sbin/sshd -T 2>/dev/null | grep -i passwordauthentication || echo 'Could not check'"
run_cmd "MaxAuthTries" "/usr/sbin/sshd -T 2>/dev/null | grep -i maxauthtries || echo 'Could not check'"
run_cmd "X11Forwarding" "/usr/sbin/sshd -T 2>/dev/null | grep -i x11forwarding || echo 'Could not check'"

subheader "SSH Authorized Keys"
run_cmd "Root authorized_keys" "cat /root/.ssh/authorized_keys 2>/dev/null || echo 'No root authorized_keys'"
run_cmd "All user authorized_keys" "find /home -name authorized_keys -exec sh -c 'echo \"=== \$1 ===\"; cat \"\$1\"; echo' _ {} \; 2>/dev/null || echo 'No user authorized_keys found'"
run_cmd "authorized_keys permissions" "find / -name authorized_keys -exec ls -la {} \; 2>/dev/null || echo 'None found'"

# ============================================================
# 7. FILE PERMISSIONS & INTEGRITY
# ============================================================

header "7. FILE PERMISSIONS & INTEGRITY"

subheader "Critical File Permissions"
run_cmd "/etc/passwd permissions" "ls -la /etc/passwd"
run_cmd "/etc/shadow permissions" "ls -la /etc/shadow"
run_cmd "/etc/group permissions" "ls -la /etc/group"
run_cmd "/etc/gshadow permissions" "ls -la /etc/gshadow"
run_cmd "/etc/sudoers permissions" "ls -la /etc/sudoers"
run_cmd "/etc/crontab permissions" "ls -la /etc/crontab"
run_cmd "/etc/ssh/sshd_config permissions" "ls -la /etc/ssh/sshd_config 2>/dev/null || echo 'not found'"

subheader "SUID / SGID Files"
run_cmd "SUID files (privilege escalation risk)" "find / -perm /4000 -type f 2>/dev/null"
run_cmd "SGID files" "find / -perm /2000 -type f 2>/dev/null"
run_cmd "SUID/SGID files (combined)" "find / -perm /6000 -type f 2>/dev/null"

subheader "World-Writable Files"
run_cmd "World-writable files (excluding system dirs)" "find / -perm -0002 -type f 2>/dev/null | grep -v '/proc\|/sys\|/dev\|/run\|/tmp' | head -50"
run_cmd "World-writable directories" "find / -perm -0002 -type d 2>/dev/null | grep -v '/proc\|/sys\|/dev\|/run\|/tmp' | head -50"

subheader "Unowned / Unowned Files"
run_cmd "Files with no owner" "find / -nouser -o -nogroup 2>/dev/null | head -50"

subheader "Recently Modified Files"
run_cmd "Files modified in last 24 hours" "find / -mtime -1 -type f 2>/dev/null | grep -v '/proc\|/sys\|/dev\|/run\|/tmp\|/var/log' | head -50"

subheader "Suspicious Executables"
run_cmd "Executables in /tmp" "find /tmp -type f -executable 2>/dev/null || echo 'None found'"
run_cmd "Executables in /var/tmp" "find /var/tmp -type f -executable 2>/dev/null || echo 'None found'"
run_cmd "Executables in /dev/shm" "find /dev/shm -type f -executable 2>/dev/null || echo 'None found'"
run_cmd "Executables in /usr/local/bin" "find /usr/local/bin -type f 2>/dev/null || echo 'None found'"
run_cmd "Executables in /usr/local/sbin" "find /usr/local/sbin -type f 2>/dev/null || echo 'None found'"
run_cmd "Executables in /opt" "find /opt -type f -executable 2>/dev/null || echo 'None found'"

subheader "File Search by Suspicious Keywords"
run_cmd "Files containing suspicious keywords" "grep -rl 'reverse\|backdoor\|/dev/tcp\|mkfifo\|netcat\|nmap\|hydra\|metasploit\|payload\|exploit\|shell_exec\|eval(base64' /home /root /tmp /var/tmp /usr/local/bin /opt 2>/dev/null | head -30"

subheader "Hacking Tools Check"
run_cmd "Known hacking tools installed" "which nc ncat nmap tcpdump wireshark hydra john hashcat aircrack-ng dsniff ettercap arpspoof macchanger nikto sqlmap gobuster dirb wpscan 2>/dev/null || echo 'No common hacking tools found in PATH'"
run_cmd "Hacking tools via dpkg" "dpkg -l 2>/dev/null | grep -iE 'nmap|hydra|john|hashcat|wireshark|tcpdump|dsniff|ettercap|aircrack|nikto|sqlmap|metasploit|kismet|dsniff|yersinia|macchanger' || echo 'No hacking tools found via dpkg'"

# Prohibited software check
if [[ -n "$PROHIBITED_PKG" ]]; then
    subheader "Prohibited Software Check"
    for pkg in $PROHIBITED_PKG; do
        result=$(dpkg -l 2>/dev/null | grep -i "$pkg")
        if [[ -n "$result" ]]; then
            log "  [!] PROHIBITED PACKAGE FOUND: $pkg"
            log "  $result"
        else
            log "  [OK] $pkg not found"
        fi
    done
fi

# Prohibited files check
if [[ -n "$PROHIBITED_FILES" ]]; then
    subheader "Prohibited Files Check"
    for f in $PROHIBITED_FILES; do
        if [[ -e "$f" ]]; then
            log "  [!] PROHIBITED FILE FOUND: $f"
            run_cmd "Details of $f" "ls -la $f"
        else
            log "  [OK] $f not found"
        fi
    done
fi

# ============================================================
# 8. CRON JOBS & SCHEDULED TASKS
# ============================================================

header "8. CRON JOBS & SCHEDULED TASKS"

subheader "System Cron"
run_cmd "System crontab" "cat /etc/crontab 2>/dev/null || echo 'No /etc/crontab'"
run_cmd "cron.d directory" "ls -la /etc/cron.d/ 2>/dev/null"
run_cmd "cron.d file contents" "for f in /etc/cron.d/*; do echo \"=== \$f ===\"; cat \"\$f\" 2>/dev/null; echo; done"
run_cmd "cron.daily" "ls -la /etc/cron.daily/ 2>/dev/null"
run_cmd "cron.hourly" "ls -la /etc/cron.hourly/ 2>/dev/null"
run_cmd "cron.weekly" "ls -la /etc/cron.weekly/ 2>/dev/null"
run_cmd "cron.monthly" "ls -la /etc/cron.monthly/ 2>/dev/null"

subheader "User Crontabs"
run_cmd "User crontab directory" "ls -la /var/spool/cron/crontabs/ 2>/dev/null || echo 'No user crontabs'"
run_cmd "User crontab contents" "for f in /var/spool/cron/crontabs/*; do echo \"=== \$f ===\"; cat \"\$f\" 2>/dev/null; echo; done 2>/dev/null || echo 'No user crontabs found'"

subheader "At Jobs"
run_cmd "Pending at jobs" "atq 2>/dev/null || echo 'at not installed'"

subheader "systemd Timers"
run_cmd "All systemd timers" "systemctl list-timers --all --no-pager"
run_cmd "Active systemd timers" "systemctl list-timers --state=active --no-pager"

# ============================================================
# 9. STARTUP SCRIPTS & PERSISTENCE
# ============================================================

header "9. STARTUP SCRIPTS & PERSISTENCE"

subheader "Enabled Services (Boot Persistence)"
run_cmd "Enabled services" "systemctl list-unit-files --state=enabled --no-pager"

subheader "Legacy Startup Scripts"
run_cmd "rc.local" "cat /etc/rc.local 2>/dev/null || echo 'No rc.local'"
run_cmd "init.d scripts" "ls -la /etc/init.d/ 2>/dev/null"

subheader "Profile Scripts (Login Persistence)"
run_cmd "/etc/profile" "cat /etc/profile 2>/dev/null"
run_cmd "/etc/bash.bashrc" "cat /etc/bash.bashrc 2>/dev/null"
run_cmd "profile.d scripts" "ls -la /etc/profile.d/ 2>/dev/null"
run_cmd "profile.d contents" "for f in /etc/profile.d/*.sh; do echo \"=== \$f ===\"; cat \"\$f\" 2>/dev/null; echo; done 2>/dev/null || echo 'No profile.d scripts'"

subheader "User Profile Scripts"
run_cmd "Root .bashrc" "cat /root/.bashrc 2>/dev/null"
run_cmd "Root .profile" "cat /root/.profile 2>/dev/null"
run_cmd "Root .bash_profile" "cat /root/.bash_profile 2>/dev/null || echo 'No root .bash_profile'"
run_cmd "User .bashrc files" "for u in \$(awk -F: '\$3 >= 1000 && \$3 < 65534 {print \$1}' /etc/passwd); do echo \"=== \$u .bashrc ===\"; cat /home/\$u/.bashrc 2>/dev/null; echo; done"
run_cmd "User .profile files" "for u in \$(awk -F: '\$3 >= 1000 && \$3 < 65534 {print \$1}' /etc/passwd); do echo \"=== \$u .profile ===\"; cat /home/\$u/.profile 2>/dev/null; echo; done"

subheader "Command History"
run_cmd "Root bash history" "cat /root/.bash_history 2>/dev/null || echo 'No root history'"
run_cmd "User bash histories" "for u in \$(awk -F: '\$3 >= 1000 && \$3 < 65534 {print \$1}' /etc/passwd); do echo \"=== \$u history ===\"; cat /home/\$u/.bash_history 2>/dev/null; echo; done"

# ============================================================
# 10. NETWORK CONFIGURATION
# ============================================================

header "10. NETWORK CONFIGURATION"

subheader "Network Interfaces"
run_cmd "IP addresses" "ip addr"
run_cmd "Routing table" "ip route"
run_cmd "ARP table" "ip neigh"
run_cmd "DNS config" "cat /etc/resolv.conf 2>/dev/null"
run_cmd "Hosts file" "cat /etc/hosts"

subheader "Network Security Settings"
run_cmd "IP forwarding status" "cat /proc/sys/net/ipv4/ip_forward"
run_cmd "IP forwarding (sysctl)" "sysctl net.ipv4.ip_forward 2>/dev/null"
run_cmd "Accept redirects" "sysctl net.ipv4.conf.all.accept_redirects 2>/dev/null"
run_cmd "Accept source route" "sysctl net.ipv4.conf.all.accept_source_route 2>/dev/null"
run_cmd "Reverse path filter" "sysctl net.ipv4.conf.all.rp_filter 2>/dev/null"
run_cmd "Log martians" "sysctl net.ipv4.conf.all.log_martians 2>/dev/null"
run_cmd "All sysctl network settings" "sysctl -a 2>/dev/null | grep -E 'ip_forward|redirects|source_route|log_martians|accept_redirects'"
run_cmd "Full sysctl.conf" "cat /etc/sysctl.conf 2>/dev/null"
run_cmd "sysctl.d files" "ls -la /etc/sysctl.d/ 2>/dev/null"
run_cmd "sysctl.d contents" "for f in /etc/sysctl.d/*.conf; do echo \"=== \$f ===\"; cat \"\$f\" 2>/dev/null; echo; done 2>/dev/null"

# ============================================================
# 11. AUTHENTICATION POLICY
# ============================================================

header "11. AUTHENTICATION POLICY"

subheader "Password Policy"
run_cmd "login.defs password settings" "grep -E 'PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE|ENCRYPT_METHOD|SHA_CRYPT_MIN_ROUNDS|SHA_CRYPT_MAX_ROUNDS' /etc/login.defs"
run_cmd "Full login.defs (relevant lines)" "grep -v '^#' /etc/login.defs | grep -v '^$'"

subheader "Password Quality"
run_cmd "pwquality.conf" "cat /etc/security/pwquality.conf 2>/dev/null || echo 'No pwquality.conf'"

subheader "PAM Configuration"
run_cmd "common-password" "cat /etc/pam.d/common-password 2>/dev/null"
run_cmd "common-auth" "cat /etc/pam.d/common-auth 2>/dev/null"
run_cmd "common-account" "cat /etc/pam.d/common-account 2>/dev/null"
run_cmd "common-session" "cat /etc/pam.d/common-session 2>/dev/null"
run_cmd "su PAM config" "cat /etc/pam.d/su 2>/dev/null"
run_cmd "sudo PAM config" "cat /etc/pam.d/sudo 2>/dev/null"
run_cmd "login PAM config" "cat /etc/pam.d/login 2>/dev/null"

# ============================================================
# 12. UPDATES & PACKAGES
# ============================================================

header "12. UPDATES & PACKAGES"

subheader "Installed Packages"
run_cmd "Total installed packages" "dpkg -l | wc -l"
run_cmd "All installed packages" "dpkg -l --no-pager"
run_cmd "Recently installed packages" "ls -lt /var/lib/dpkg/info/*.list 2>/dev/null | head -30"

subheader "Available Updates"
run_cmd "Update check (apt update)" "apt update 2>&1"
run_cmd "Upgradable packages" "apt list --upgradable 2>/dev/null"

subheader "Package Search"
run_cmd "Network tools installed" "dpkg -l | grep -iE 'nmap|wireshark|tcpdump|netcat|net-tools|bind9|dnsmasq|samba|vsftpd|proftpd|apache2|nginx|telnet|rsh|snmp|cups|avahi|bluetooth|postfix|dovecot|slapd|squid' 2>/dev/null || echo 'None found'"

# ============================================================
# 13. LOGS & FORENSIC EVIDENCE
# ============================================================

header "13. LOGS & FORENSIC EVIDENCE"

subheader "Authentication Log"
run_cmd "Recent auth log (last 100 lines)" "tail -100 /var/log/auth.log 2>/dev/null || echo 'auth.log not found'"
run_cmd "Failed login attempts" "grep -i 'failed\|invalid\|error' /var/log/auth.log 2>/dev/null | tail -30 || echo 'No auth.log or no failed attempts'"
run_cmd "Sudo usage in logs" "grep -i 'sudo' /var/log/auth.log 2>/dev/null | tail -30 || echo 'No sudo entries found'"

subheader "System Log"
run_cmd "Recent syslog (last 100 lines)" "tail -100 /var/log/syslog 2>/dev/null || echo 'syslog not found'"

subheader "Kernel Log"
run_cmd "Recent kernel messages" "dmesg 2>/dev/null | tail -50 || echo 'dmesg not available'"

subheader "Login History"
run_cmd "Last logins" "last 2>/dev/null || echo 'last not available'"
run_cmd "Failed login attempts (lastb)" "lastb 2>/dev/null | head -30 || echo 'lastb not available'"
run_cmd "Currently logged in users" "who"

subheader "Hidden Files"
run_cmd "Hidden files in /home" "find /home -name '.*' -type f 2>/dev/null | head -30"
run_cmd "Hidden files in /root" "find /root -name '.*' -type f 2>/dev/null | head -30"
run_cmd "Hidden files in /tmp" "find /tmp -name '.*' -type f 2>/dev/null | head -30"
run_cmd "Hidden files in /var/tmp" "find /var/tmp -name '.*' -type f 2>/dev/null | head -30"

subheader "Large Files"
run_cmd "Large files (>10MB, excluding system dirs)" "find / -size +10M -type f 2>/dev/null | grep -v '/proc\|/sys\|/dev\|/usr/lib\|/usr/share\|/var/lib\|/boot' | head -30"

# ============================================================
# 14. FIREFOX / BROWSER SETTINGS
# ============================================================

header "14. BROWSER SETTINGS"

run_cmd "Firefox installed?" "dpkg -l | grep firefox || echo 'Firefox not installed'"
run_cmd "Firefox syspref.js" "cat /etc/firefox/syspref.js 2>/dev/null || echo 'No syspref.js'"
run_cmd "Firefox auto-update setting" "grep -r 'app.update' /etc/firefox/ 2>/dev/null || echo 'No Firefox config found'"

# ============================================================
# 15. SUMMARY
# ============================================================

header "AUDIT SUMMARY"

echo "Audit complete." | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"
echo "Report saved to: $REPORT_FILE" | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"
echo "Review the report and identify findings that violate the README." | tee -a "$REPORT_FILE"
echo "Use the CyberPatriot Linux Workflow document to apply fixes." | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"
echo "Key things to review:" | tee -a "$REPORT_FILE"
echo "  1. Unauthorized users or admins (Section 2)" | tee -a "$REPORT_FILE"
echo "  2. Sudo configuration issues (Section 3)" | tee -a "$REPORT_FILE"
echo "  3. Unnecessary services running (Section 4)" | tee -a "$REPORT_FILE"
echo "  4. Missing or misconfigured firewall (Section 5)" | tee -a "$REPORT_FILE"
echo "  5. SSH security settings (Section 6)" | tee -a "$REPORT_FILE"
echo "  6. File permission issues (Section 7)" | tee -a "$REPORT_FILE"
echo "  7. Suspicious cron jobs or persistence (Sections 8-9)" | tee -a "$REPORT_FILE"
echo "  8. Network security settings (Section 10)" | tee -a "$REPORT_FILE"
echo "  9. Password policy gaps (Section 11)" | tee -a "$REPORT_FILE"
echo " 10. Prohibited software or files (Sections 7, 12)" | tee -a "$REPORT_FILE"
echo " 11. Forensic evidence (Section 13)" | tee -a "$REPORT_FILE"

echo ""
echo -e "${GREEN}${BOLD}Audit complete!${NC}"
echo -e "${YELLOW}Full report: ${REPORT_FILE}${NC}"
echo ""
echo "Review the report, then apply fixes using the workflow document."
