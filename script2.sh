#!/usr/bin/env bash
#
# CyberPatriot Linux Security Audit + Auto-Fix Script
# Distribution: Ubuntu / Debian / Linux Mint
# Mode: Interactive README prompts, then fully automated inspect + fix
#
# Usage:
#   sudo bash cp-audit-fix.sh
#
# Output:
#   - Full report saved to ~/cp-audit-fix-YYYYMMDD-HHMMSS.txt
#   - On-screen summary of findings and fixes applied
#
# ============================================================

set -o pipefail

# ---------- Setup ----------

REPORT_DIR="$HOME"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
REPORT_FILE="${REPORT_DIR}/cp-audit-fix-${TIMESTAMP}.txt"
CHANGE_LOG="${REPORT_DIR}/cp-changelog-${TIMESTAMP}.txt"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ---------- Helper Functions ----------

log() {
    echo -e "$1" | tee -a "$REPORT_FILE"
}

header() {
    echo "" | tee -a "$REPORT_FILE"
    echo "==============================================================" | tee -a "$REPORT_FILE"
    echo "  $1" | tee -a "$REPORT_FILE"
    echo "==============================================================" | tee -a "$REPORT_FILE"
}

subheader() {
    echo "" | tee -a "$REPORT_FILE"
    echo "--- $1 ---" | tee -a "$REPORT_FILE"
}

# Run a command and capture output
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

# Record a change in the change log
change() {
    local finding="$1"
    local reason="$2"
    local action="$3"
    local verify="$4"
    echo "[FINDING] $finding" >> "$CHANGE_LOG"
    echo "[REASON]  $reason" >> "$CHANGE_LOG"
    echo "[ACTION]  $action" >> "$CHANGE_LOG"
    echo "[VERIFY]  $verify" >> "$CHANGE_LOG"
    echo "---" >> "$CHANGE_LOG"
    log "${GREEN}[FIXED]${NC} $finding"
}

# Record a finding that was NOT fixed (needs manual attention)
finding() {
    local desc="$1"
    local detail="$2"
    echo "[MANUAL]  $desc" >> "$CHANGE_LOG"
    echo "[DETAIL]  $detail" >> "$CHANGE_LOG"
    echo "---" >> "$CHANGE_LOG"
    log "${RED}[MANUAL REVIEW NEEDED]${NC} $desc"
}

# ---------- Root Check ----------

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}${BOLD}This script must be run as root.${NC}"
    echo "Run with: sudo bash cp-audit-fix.sh"
    exit 1
fi

# ---------- Initialize Report ----------

echo "CyberPatriot Linux Security Audit + Auto-Fix Report" > "$REPORT_FILE"
echo "Date: $(date)" >> "$REPORT_FILE"
echo "Host: $(hostname)" >> "$REPORT_FILE"
echo "User: $(whoami)" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

echo "# CyberPatriot Change Log" > "$CHANGE_LOG"
echo "Date: $(date)" >> "$CHANGE_LOG"
echo "Host: $(hostname)" >> "$CHANGE_LOG"
echo "" >> "$CHANGE_LOG"

# ---------- Interactive README Input ----------

header "README / SCENARIO INPUT"

echo -e "${CYAN}Enter the details from the README. Press Enter to skip any field.${NC}"
echo ""

read -p "Authorized users (space-separated usernames): " AUTH_USERS
read -p "Authorized administrators (space-separated): " AUTH_ADMINS
read -p "Required services (space-separated, e.g. ssh apache2): " REQ_SERVICES
read -p "Prohibited software/packages (space-separated): " PROHIBITED_PKG
read -p "Prohibited files/directories (space-separated paths): " PROHIBITED_FILES

echo ""
echo -e "${GREEN}${BOLD}Starting automated audit + fix...${NC}"
echo -e "${YELLOW}Report:     ${REPORT_FILE}${NC}"
echo -e "${YELLOW}Change log: ${CHANGE_LOG}${NC}"
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
# 2. USER & GROUP AUDIT + FIXES
# ============================================================

header "2. USER & GROUP AUDIT + FIXES"

subheader "User Accounts"

run_cmd "All users (getent passwd)" "getent passwd"
run_cmd "Human accounts (UID >= 1000)" "awk -F: '\$3 >= 1000 && \$3 < 65534 {print \$1, \$3, \$6, \$7}' /etc/passwd"
run_cmd "Accounts with UID 0 (should be root only)" "awk -F: '\$3 == 0 {print \$1}' /etc/passwd"

# --- FIX: Remove UID 0 from non-root accounts ---
for u in $(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd); do
    new_uid=$(awk 'BEGIN{max=999} {if($3>max && $3<1000) max=$3} END{print max+1}' /etc/passwd)
    change "User '$u' has UID 0 (root privilege)" \
           "Only root should have UID 0" \
           "usermod -u $new_uid $u" \
           "awk -F: '\$3==0{print \$1}' /etc/passwd — should show only root"
    usermod -u "$new_uid" "$u" 2>/dev/null
done

# --- FIX: Disable/lock unauthorized users ---
if [[ -n "$AUTH_USERS" ]]; then
    subheader "Authorized User Comparison"
    log "Authorized users from README: $AUTH_USERS"
    log ""

    # Find unauthorized users
    for u in $(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd); do
        if ! echo "$AUTH_USERS" | grep -qw "$u"; then
            log "${RED}[!] UNAUTHORIZED USER: $u${NC}"
            # Lock the account (don't delete — preserve for forensics)
            change "Unauthorized user '$u' found on system" \
                   "Not in README authorized users list" \
                   "passwd -l $u; usermod -s /usr/sbin/nologin $u; chage -E 1 $u" \
                   "passwd -S $u — should show locked status"
            passwd -l "$u" 2>/dev/null
            usermod -s /usr/sbin/nologin "$u" 2>/dev/null
            chage -E 1 "$u" 2>/dev/null
        fi
    done

    # Check for missing authorized users
    for u in $AUTH_USERS; do
        if ! getent passwd "$u" >/dev/null 2>&1; then
            finding "Authorized user '$u' is missing from the system" \
                    "README requires this user to exist"
        fi
    done
fi

# --- FIX: Empty passwords ---
for u in $(awk -F: '($2 == "" || $2 == "*") && $3 >= 1000 && $3 < 65534 {print $1}' /etc/shadow); do
    change "User '$u' has an empty or unset password" \
           "Empty passwords are a security risk" \
           "passwd -l $u (locked — set a real password if user is authorized)" \
           "passwd -S $u"
    passwd -l "$u" 2>/dev/null
done

# --- Password status for all users ---
run_cmd "Password status for all users" "for u in \$(awk -F: '\$3 >= 1000 && \$3 < 65534 {print \$1}' /etc/passwd); do echo -n \"\$u: \"; passwd -S \$u 2>/dev/null; done"

subheader "Groups & Administrative Access"

run_cmd "sudo group members" "getent group sudo"
run_cmd "admin group members" "getent group admin 2>/dev/null || echo 'admin group not found'"
run_cmd "wheel group members" "getent group wheel 2>/dev/null || echo 'wheel group not found'"

# --- FIX: Remove unauthorized admins from sudo/admin/wheel groups ---
if [[ -n "$AUTH_ADMINS" ]]; then
    subheader "Authorized Admin Comparison"
    log "Authorized admins from README: $AUTH_ADMINS"
    log ""

    for group_name in sudo admin wheel; do
        members=$(getent group "$group_name" 2>/dev/null | cut -d: -f4 | tr ',' '\n' | sed 's/^ *//;s/ *$//')
        for u in $members; do
            if [[ -n "$u" ]] && ! echo "$AUTH_ADMINS" | grep -qw "$u"; then
                change "User '$u' is in the '$group_name' group but is not an authorized admin" \
                       "README does not list '$u' as an authorized administrator" \
                       "gpasswd -d $u $group_name" \
                       "getent group $group_name — '$u' should not appear"
                gpasswd -d "$u" "$group_name" 2>/dev/null
            fi
        done
    done

    # Ensure authorized admins are in sudo group
    for u in $AUTH_ADMINS; do
        if getent passwd "$u" >/dev/null 2>&1; then
            if ! getent group sudo | grep -qw "$u"; then
                change "Authorized admin '$u' is not in the sudo group" \
                       "README lists '$u' as an authorized admin" \
                       "gpasswd -a $u sudo" \
                       "getent group sudo — '$u' should appear"
                gpasswd -a "$u" sudo 2>/dev/null
            fi
        fi
    done
fi

subheader "Password Aging"

run_cmd "Global password policy (login.defs)" "grep -E 'PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE' /etc/login.defs"
for u in $(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd); do
    run_cmd "Password aging for $u" "chage -l $u"
done

# --- FIX: Password aging for all human users ---
for u in $(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd); do
    max_days=$(chage -l "$u" 2>/dev/null | grep "Maximum number" | awk -F: '{print $2}' | tr -d ' ')
    if [[ "$max_days" == "99999" || "$max_days" == "" ]]; then
        change "User '$u' password never expires (max days = $max_days)" \
               "Passwords should expire periodically" \
               "chage -M 90 $u" \
               "chage -l $u — Maximum should be 90"
        chage -M 90 "$u" 2>/dev/null
    fi
done

# ============================================================
# 3. SUDO CONFIGURATION + FIXES
# ============================================================

header "3. SUDO CONFIGURATION + FIXES"

run_cmd "Main sudoers file" "cat /etc/sudoers"
run_cmd "sudoers.d directory listing" "ls -la /etc/sudoers.d/"
run_cmd "Sudoers syntax validation" "visudo -c"
run_cmd "All NOPASSWD entries (security risk)" "grep -rn 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null || echo 'No NOPASSWD entries found'"
run_cmd "All sudo privilege grants" "grep -rn 'ALL=(ALL\|ALL=(root' /etc/sudoers /etc/sudoers.d/ 2>/dev/null || echo 'None found'"

# --- FIX: Remove NOPASSWD entries from sudoers.d files ---
for f in /etc/sudoers.d/*; do
    if [[ -f "$f" ]] && grep -q 'NOPASSWD' "$f" 2>/dev/null; then
        change "NOPASSWD entry found in $f" \
               "NOPASSWD allows running commands without password — security risk" \
               "Commented out NOPASSWD lines in $f" \
               "grep NOPASSWD $f — should return nothing"
        sed -i 's/^\([^#].*NOPASSWD.*\)/# \1/' "$f"
    fi
done

# --- FIX: Remove sudoers.d files granting access to unauthorized users ---
if [[ -n "$AUTH_USERS$AUTH_ADMINS" ]]; then
    for f in /etc/sudoers.d/*; do
        [[ -f "$f" ]] || continue
        while IFS= read -r line; do
            user=$(echo "$line" | awk '{print $1}')
            if [[ -n "$user" && "$user" != "root" && "$user" != "%"* && "$user" != "Defaults"* && "$user" != "#" ]]; then
                if ! echo "$AUTH_USERS $AUTH_ADMINS" | grep -qw "$user"; then
                    change "Sudoers file $f grants privileges to unauthorized user '$user'" \
                           "$user is not in README authorized users/admins list" \
                           "Commented out line for $user in $f" \
                           "visudo -c — should pass"
                    sed -i "s/^${user}\b/# ${user}/" "$f"
                fi
            fi
        done < "$f"
    done
fi

# Validate sudoers after changes
run_cmd "Sudoers validation after fixes" "visudo -c"

# ============================================================
# 4. SERVICES & PORTS + FIXES
# ============================================================

header "4. SERVICES & PORTS + FIXES"

subheader "Running Services"

run_cmd "Running services" "systemctl --type=service --state=running --no-pager"
run_cmd "Enabled services (start at boot)" "systemctl list-unit-files --type=service --state=enabled --no-pager"

subheader "Listening Ports"

run_cmd "All listening ports with processes" "ss -tulpn"
run_cmd "All active connections" "ss -tuna"

# --- FIX: Disable common unnecessary services ---
UNNECESSARY_SERVICES="telnet rsh rlogin rexec talk ntalk vsftpd proftpd snmpd cups avahi-daemon bluetooth smbd nmbd rpcbind nfs-common slapd squid dansguardian postfix dovecot"

for svc in $UNNECESSARY_SERVICES; do
    status=$(systemctl is-enabled "$svc" 2>/dev/null)
    if [[ "$status" == "enabled" ]]; then
        # Check if this service is in the required list
        if echo "$REQ_SERVICES" | grep -qw "$svc"; then
            log "${YELLOW}[SKIP]${NC} $svc is enabled but is a required service — keeping it"
        else
            change "Unnecessary service '$svc' is enabled" \
                   "Not in README required services list" \
                   "systemctl disable --now $svc" \
                   "systemctl is-enabled $svc — should be disabled"
            systemctl disable --now "$svc" 2>/dev/null
        fi
    fi
done

# --- Ensure required services are running ---
if [[ -n "$REQ_SERVICES" ]]; then
    subheader "Required Services Check + Fix"
    for svc in $REQ_SERVICES; do
        status=$(systemctl is-active "$svc" 2>/dev/null)
        if [[ "$status" != "active" ]]; then
            change "Required service '$svc' is not running" \
                   "README requires this service to be active" \
                   "systemctl enable --now $svc" \
                   "systemctl status $svc"
            systemctl enable --now "$svc" 2>/dev/null
        else
            log "${GREEN}[OK]${NC} Required service '$svc' is running"
        fi
    done
fi

# ============================================================
# 5. FIREWALL + FIXES
# ============================================================

header "5. FIREWALL + FIXES"

run_cmd "UFW status" "ufw status verbose 2>/dev/null || echo 'UFW not available'"
run_cmd "iptables rules" "iptables -L -n -v"

# --- FIX: Enable firewall with required service rules ---
ufw_status=$(ufw status 2>/dev/null | head -1)
if [[ "$ufw_status" == *"inactive"* ]] || [[ "$ufw_status" == "" ]]; then
    log "${YELLOW}[!] Firewall is not active — configuring...${NC}"

    # Set default policies
    ufw default deny incoming 2>/dev/null
    ufw default allow outgoing 2>/dev/null

    # Allow required services before enabling
    if [[ -n "$REQ_SERVICES" ]]; then
        for svc in $REQ_SERVICES; do
            # Map common service names to UFW profiles/ports
            case "$svc" in
                ssh|sshd|openssh-server)
                    ufw allow OpenSSH 2>/dev/null
                    log "  Allowed OpenSSH (port 22)"
                    ;;
                apache2|httpd)
                    ufw allow 80/tcp 2>/dev/null
                    log "  Allowed port 80 (HTTP)"
                    ;;
                nginx)
                    ufw allow 80/tcp 2>/dev/null
                    log "  Allowed port 80 (HTTP)"
                    ;;
                *)
                    log "  [!] Could not auto-determine port for '$svc' — allow manually if needed"
                    ;;
            esac
        done
    fi

    # Enable UFW
    echo "y" | ufw enable 2>/dev/null
    change "Firewall was not active" \
           "No firewall protection" \
           "ufw default deny incoming; ufw default allow outgoing; ufw allow required services; ufw enable" \
           "ufw status verbose"

    run_cmd "UFW status after enabling" "ufw status verbose"
else
    log "${GREEN}[OK]${NC} Firewall is already active"
    run_cmd "UFW status" "ufw status verbose"
fi

# ============================================================
# 6. SSH CONFIGURATION + FIXES
# ============================================================

header "6. SSH CONFIGURATION + FIXES"

ssh_installed=$(dpkg -l 2>/dev/null | grep openssh-server)

if [[ -z "$ssh_installed" ]]; then
    log "OpenSSH server is not installed"
    # Check if SSH is required
    if echo "$REQ_SERVICES" | grep -qw "ssh\|sshd\|openssh-server"; then
        finding "SSH is required by README but not installed" \
                "Install with: apt install openssh-server"
    fi
else
    run_cmd "SSH service status" "systemctl status ssh 2>/dev/null || systemctl status sshd 2>/dev/null"
    run_cmd "SSH config file" "cat /etc/ssh/sshd_config 2>/dev/null"
    run_cmd "SSH drop-in config files" "ls -la /etc/ssh/sshd_config.d/ 2>/dev/null && for f in /etc/ssh/sshd_config.d/*.conf; do echo \"=== \$f ===\"; cat \"\$f\" 2>/dev/null; echo; done || echo 'No drop-in configs'"
    run_cmd "SSH config validation" "/usr/sbin/sshd -t 2>&1"

    subheader "Key SSH Security Settings"

    run_cmd "PermitRootLogin" "/usr/sbin/sshd -T 2>/dev/null | grep -i permitrootlogin || echo 'Could not check'"
    run_cmd "PermitEmptyPasswords" "/usr/sbin/sshd -T 2>/dev/null | grep -i permitemptypasswords || echo 'Could not check'"
    run_cmd "PasswordAuthentication" "/usr/sbin/sshd -T 2>/dev/null | grep -i passwordauthentication || echo 'Could not check'"
    run_cmd "MaxAuthTries" "/usr/sbin/sshd -T 2>/dev/null | grep -i maxauthtries || echo 'Could not check'"

    # --- FIX: Harden SSH configuration ---
    sshd_config="/etc/ssh/sshd_config"

    # Check if SSH is required
    ssh_required=false
    if echo "$REQ_SERVICES" | grep -qw "ssh sshd openssh-server"; then
        ssh_required=true
    fi

    # Fix PermitRootLogin
    current_setting=$(/usr/sbin/sshd -T 2>/dev/null | grep -i permitrootlogin | awk '{print $2}')
    if [[ "$current_setting" == "yes" || "$current_setting" == "prohibit-password" ]]; then
        change "SSH PermitRootLogin is set to '$current_setting'" \
               "Root should not be able to login directly via SSH" \
               "Set PermitRootLogin no in $sshd_config" \
               "/usr/sbin/sshd -T | grep permitrootlogin — should show 'no'"
        if grep -qi "^#*PermitRootLogin" "$sshd_config"; then
            sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' "$sshd_config"
        else
            echo "PermitRootLogin no" >> "$sshd_config"
        fi
    fi

    # Fix PermitEmptyPasswords
    current_setting=$(/usr/sbin/sshd -T 2>/dev/null | grep -i permitemptypasswords | awk '{print $2}')
    if [[ "$current_setting" == "yes" ]]; then
        change "SSH PermitEmptyPasswords is set to 'yes'" \
               "Empty passwords should never be allowed for SSH" \
               "Set PermitEmptyPasswords no in $sshd_config" \
               "/usr/sbin/sshd -T | grep permitemptypasswords — should show 'no'"
        if grep -qi "^#*PermitEmptyPasswords" "$sshd_config"; then
            sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$sshd_config"
        else
            echo "PermitEmptyPasswords no" >> "$sshd_config"
        fi
    fi

    # Fix MaxAuthTries
    current_setting=$(/usr/sbin/sshd -T 2>/dev/null | grep -i maxauthtries | awk '{print $2}')
    if [[ -n "$current_setting" && "$current_setting" -gt 3 ]] 2>/dev/null; then
        change "SSH MaxAuthTries is set to '$current_setting'" \
               "Too many auth attempts allows brute force" \
               "Set MaxAuthTries 3 in $sshd_config" \
               "/usr/sbin/sshd -T | grep maxauthtries — should show '3'"
        if grep -qi "^#*MaxAuthTries" "$sshd_config"; then
            sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/' "$sshd_config"
        else
            echo "MaxAuthTries 3" >> "$sshd_config"
        fi
    fi

    # Validate and restart SSH after changes
    sshd_check=$(/usr/sbin/sshd -t 2>&1)
    if [[ -z "$sshd_check" ]]; then
        run_cmd "SSH config validation after fixes" "/usr/sbin/sshd -t"
        systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
        run_cmd "SSH service status after restart" "systemctl status ssh 2>/dev/null || systemctl status sshd 2>/dev/null"
    else
        log "${RED}[!] SSH config validation FAILED after fixes:${NC} $sshd_check"
        finding "SSH config validation failed after applying fixes" \
                "Manual review of $sshd_config required: $sshd_check"
    fi

    subheader "SSH Authorized Keys"

    run_cmd "Root authorized_keys" "cat /root/.ssh/authorized_keys 2>/dev/null || echo 'No root authorized_keys'"
    run_cmd "All user authorized_keys" "find /home -name authorized_keys -exec sh -c 'echo \"=== \$1 ===\"; cat \"\$1\"; echo' _ {} \; 2>/dev/null || echo 'No user authorized_keys found'"

    # --- FIX: Remove unauthorized SSH keys ---
    for keyfile in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
        if [[ -f "$keyfile" ]]; then
            owner=$(stat -c '%U' "$keyfile")
            if echo "$AUTH_USERS $AUTH_ADMINS" | grep -qw "$owner" || [[ "$owner" == "root" ]]; then
                log "${GREEN}[OK]${NC} authorized_keys for $owner appears authorized"
            else
                change "SSH authorized_keys found for '$owner' who is not an authorized user" \
                       "Unauthorized SSH key access" \
                       "Removed $keyfile" \
                       "File should not exist"
                rm "$keyfile" 2>/dev/null
            fi
        fi
    done
fi

# ============================================================
# 7. FILE PERMISSIONS + FIXES
# ============================================================

header "7. FILE PERMISSIONS + INTEGRITY + FIXES"

subheader "Critical File Permissions"

run_cmd "/etc/passwd permissions" "ls -la /etc/passwd"
run_cmd "/etc/shadow permissions" "ls -la /etc/shadow"
run_cmd "/etc/group permissions" "ls -la /etc/group"
run_cmd "/etc/gshadow permissions" "ls -la /etc/gshadow"
run_cmd "/etc/sudoers permissions" "ls -la /etc/sudoers"
run_cmd "/etc/crontab permissions" "ls -la /etc/crontab"
run_cmd "/etc/ssh/sshd_config permissions" "ls -la /etc/ssh/sshd_config 2>/dev/null"

# --- FIX: Correct critical file permissions ---
declare -a CRITICAL_FILES=(
    "/etc/passwd:644:root:root"
    "/etc/shadow:640:root:shadow"
    "/etc/group:644:root:root"
    "/etc/gshadow:640:root:shadow"
    "/etc/sudoers:440:root:root"
    "/etc/crontab:644:root:root"
)

for entry in "${CRITICAL_FILES[@]}"; do
    filepath=$(echo "$entry" | cut -d: -f1)
    desired_perm=$(echo "$entry" | cut -d: -f2)
    desired_owner=$(echo "$entry" | cut -d: -f3)

    if [[ -f "$filepath" ]]; then
        current_perm=$(stat -c '%a' "$filepath")
        current_owner=$(stat -c '%U:%G' "$filepath")

        if [[ "$current_perm" != "$desired_perm" ]]; then
            change "File $filepath has permissions $current_perm (should be $desired_perm)" \
                   "Incorrect permissions on critical system file" \
                   "chmod $desired_perm $filepath" \
                   "stat -c '%a' $filepath — should be $desired_perm"
            chmod "$desired_perm" "$filepath" 2>/dev/null
        fi

        if [[ "$current_owner" != "$desired_owner" ]]; then
            change "File $filepath is owned by $current_owner (should be $desired_owner)" \
                   "Incorrect ownership on critical system file" \
                   "chown $desired_owner $filepath" \
                   "stat -c '%U:%G' $filepath — should be $desired_owner"
            chown "$desired_owner" "$filepath" 2>/dev/null
        fi
    fi
done

# --- FIX: /etc/ssh/sshd_config permissions ---
if [[ -f "/etc/ssh/sshd_config" ]]; then
    current_perm=$(stat -c '%a' "/etc/ssh/sshd_config")
    if [[ "$current_perm" != "644" ]]; then
        change "/etc/ssh/sshd_config has permissions $current_perm (should be 644)" \
               "Incorrect permissions on SSH config" \
               "chmod 644 /etc/ssh/sshd_config" \
               "stat -c '%a' /etc/ssh/sshd_config"
        chmod 644 /etc/ssh/sshd_config 2>/dev/null
    fi
fi

subheader "SUID / SGID Files"

run_cmd "SUID files" "find / -perm /4000 -type f 2>/dev/null"
run_cmd "SGID files" "find / -perm /2000 -type f 2>/dev/null"

# --- FIX: Remove suspicious SUID/SGID bits ---
# Known legitimate SUID binaries (do NOT touch these)
LEGIT_SUID="/bin/su /bin/ping /bin/ping6 /usr/bin/passwd /usr/bin/sudo /usr/bin/chsh /usr/bin/chfn /usr/bin/chage /usr/bin/gpasswd /usr/bin/newgrp /usr/sbin/pppd /usr/lib/openssh/ssh-keysign /usr/bin/pkexec /usr/bin/mount /usr/bin/umount /bin/mount /bin/umount /sbin/mount.nfs"

find / -perm /4000 -type f 2>/dev/null | while read -r f; do
    if ! echo "$LEGIT_SUID" | grep -qw "$f"; then
        change "File '$f' has SUID bit set and is not a known legitimate SUID binary" \
               "Unexpected SUID could allow privilege escalation" \
               "chmod u-s $f" \
               "stat -c '%a' $f — SUID bit should be removed"
        chmod u-s "$f" 2>/dev/null
    fi
done

subheader "World-Writable Files"

run_cmd "World-writable files" "find / -perm -0002 -type f 2>/dev/null | grep -v '/proc\|/sys\|/dev\|/run\|/tmp' | head -50"

# --- FIX: Remove world-writable bit from non-system files ---
find / -perm -0002 -type f 2>/dev/null | grep -v '/proc\|/sys\|/dev\|/run\|/tmp\|/var/tmp' | while read -r f; do
    change "File '$f' is world-writable" \
           "World-writable files are a security risk" \
           "chmod o-w $f" \
           "stat -c '%a' $f — should not have 'w' in last position"
    chmod o-w "$f" 2>/dev/null
done

subheader "Suspicious Executables & Files"

run_cmd "Executables in /tmp" "find /tmp -type f -executable 2>/dev/null"
run_cmd "Executables in /var/tmp" "find /var/tmp -type f -executable 2>/dev/null"
run_cmd "Executables in /dev/shm" "find /dev/shm -type f -executable 2>/dev/null"
run_cmd "Executables in /usr/local/bin" "find /usr/local/bin -type f 2>/dev/null"
run_cmd "Executables in /usr/local/sbin" "find /usr/local/sbin -type f 2>/dev/null"
run_cmd "Executables in /opt" "find /opt -type f -executable 2>/dev/null"
run_cmd "Files containing suspicious keywords" "grep -rl 'reverse\|backdoor\|/dev/tcp\|mkfifo\|netcat\|nmap\|hydra\|metasploit\|payload\|exploit\|shell_exec\|eval(base64' /home /root /tmp /var/tmp /usr/local/bin /opt 2>/dev/null | head -30"

subheader "Hacking Tools Check"

run_cmd "Known hacking tools in PATH" "which nc ncat nmap tcpdump wireshark hydra john hashcat aircrack-ng dsniff ettercap arpspoof macchanger nikto sqlmap gobuster dirb wpscan 2>/dev/null || echo 'No common hacking tools found in PATH'"
run_cmd "Hacking tools via dpkg" "dpkg -l 2>/dev/null | grep -iE 'nmap|hydra|john|hashcat|wireshark|tcpdump|dsniff|ettercap|aircrack|nikto|sqlmap|metasploit|kismet|yersinia|macchanger' || echo 'No hacking tools found via dpkg'"

# --- FIX: Remove hacking tools ---
HACKING_TOOLS="nmap hydra john hashcat wireshark tcpdump dsniff ettercap aircrack-ng nikto sqlmap metasploit-framework kismet yersinia macchanger"

for tool in $HACKING_TOOLS; do
    if dpkg -l 2>/dev/null | grep -qi "$tool"; then
        change "Hacking tool '$tool' is installed" \
               "Prohibited security tooling" \
               "apt remove --purge $tool -y" \
               "dpkg -l | grep $tool — should return nothing"
        apt remove --purge "$tool" -y 2>/dev/null
    fi
done

# --- FIX: Remove prohibited packages ---
if [[ -n "$PROHIBITED_PKG" ]]; then
    subheader "Prohibited Software Check + Fix"
    for pkg in $PROHIBITED_PKG; do
        if dpkg -l 2>/dev/null | grep -qi "$pkg"; then
            change "Prohibited package '$pkg' is installed" \
                   "README prohibits this software" \
                   "apt remove --purge $pkg -y" \
                   "dpkg -l | grep $pkg — should return nothing"
            apt remove --purge "$pkg" -y 2>/dev/null
        fi
    done
fi

# --- FIX: Remove prohibited files ---
if [[ -n "$PROHIBITED_FILES" ]]; then
    subheader "Prohibited Files Check + Fix"
    for f in $PROHIBITED_FILES; do
        if [[ -e "$f" ]]; then
            change "Prohibited file/directory found: $f" \
                   "README prohibits this file" \
                   "rm -rf $f" \
                   "ls $f — should not exist"
            rm -rf "$f" 2>/dev/null
        fi
    done
fi

# ============================================================
# 8. CRON JOBS + FIXES
# ============================================================

header "8. CRON JOBS & SCHEDULED TASKS + FIXES"

subheader "System Cron"

run_cmd "System crontab" "cat /etc/crontab 2>/dev/null"
run_cmd "cron.d directory" "ls -la /etc/cron.d/ 2>/dev/null"
run_cmd "cron.d file contents" "for f in /etc/cron.d/*; do echo \"=== \$f ===\"; cat \"\$f\" 2>/dev/null; echo; done"

# --- FIX: Remove suspicious cron entries ---
# Common suspicious patterns in crontab
for f in /etc/crontab /etc/cron.d/*; do
    [[ -f "$f" ]] || continue
    if grep -qiE 'nc -|/dev/tcp|mkfifo|bash -i|python -c|perl -e|ruby -e|netcat|reverse|backdoor|/tmp/\.|wget.*\|.*sh|curl.*\|.*sh' "$f" 2>/dev/null; then
        change "Suspicious cron entry found in $f" \
               "Cron job contains patterns associated with reverse shells or backdoors" \
               "Commented out suspicious lines in $f" \
               "grep suspicious $f — should return nothing"
        sed -i '/nc -\|\/dev\/tcp\|mkfifo\|bash -i\|python -c\|perl -e\|ruby -e\|netcat\|reverse\|backdoor\|wget.*|.*sh\|curl.*|.*sh/s/^/# DISABLED: /' "$f"
    fi
done

subheader "User Crontabs"

run_cmd "User crontab directory" "ls -la /var/spool/cron/crontabs/ 2>/dev/null || echo 'No user crontabs'"
run_cmd "User crontab contents" "for f in /var/spool/cron/crontabs/*; do echo \"=== \$f ===\"; cat \"\$f\" 2>/dev/null; echo; done 2>/dev/null"

# --- FIX: Remove suspicious user crontabs ---
for f in /var/spool/cron/crontabs/*; do
    [[ -f "$f" ]] || continue
    if grep -qiE 'nc -|/dev/tcp|mkfifo|bash -i|python -c|perl -e|ruby -e|netcat|reverse|backdoor|/tmp/\.|wget.*\|.*sh|curl.*\|.*sh' "$f" 2>/dev/null; then
        owner=$(basename "$f")
        change "Suspicious crontab for user '$owner'" \
               "User crontab contains reverse shell or backdoor patterns" \
               "crontab -r -u $owner" \
               "ls /var/spool/cron/crontabs/ — $owner should not appear"
        crontab -r -u "$owner" 2>/dev/null
    fi
done

subheader "systemd Timers"

run_cmd "All systemd timers" "systemctl list-timers --all --no-pager"

# ============================================================
# 9. STARTUP SCRIPTS + FIXES
# ============================================================

header "9. STARTUP SCRIPTS & PERSISTENCE + FIXES"

subheader "Profile Scripts"

run_cmd "/etc/profile" "cat /etc/profile 2>/dev/null"
run_cmd "/etc/bash.bashrc" "cat /etc/bash.bashrc 2>/dev/null"
run_cmd "profile.d scripts" "ls -la /etc/profile.d/ 2>/dev/null"
run_cmd "profile.d contents" "for f in /etc/profile.d/*.sh; do echo \"=== \$f ===\"; cat \"\$f\" 2>/dev/null; echo; done 2>/dev/null"

# --- FIX: Check for suspicious entries in profile scripts ---
for f in /etc/profile /etc/bash.bashrc /etc/profile.d/*.sh /root/.bashrc /root/.profile /root/.bash_profile; do
    [[ -f "$f" ]] || continue
    if grep -qiE 'nc -|/dev/tcp|mkfifo|bash -i|python -c|perl -e|ruby -e|netcat|reverse|backdoor|/tmp/\.|wget.*\|.*sh|curl.*\|.*sh' "$f" 2>/dev/null; then
        change "Suspicious entry found in $f" \
               "Startup script contains reverse shell or backdoor patterns" \
               "Commented out suspicious lines in $f" \
               "grep suspicious $f — should return nothing"
        sed -i '/nc -\|\/dev\/tcp\|mkfifo\|bash -i\|python -c\|perl -e\|ruby -e\|netcat\|reverse\|backdoor\|wget.*|.*sh\|curl.*|.*sh/s/^/# DISABLED: /' "$f"
    fi
done

# --- FIX: Check user bashrc/profile files ---
for u in $(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd); do
    for f in /home/$u/.bashrc /home/$u/.profile /home/$u/.bash_profile; do
        [[ -f "$f" ]] || continue
        if grep -qiE 'nc -|/dev/tcp|mkfifo|bash -i|python -c|perl -e|ruby -e|netcat|reverse|backdoor|/tmp/\.|wget.*\|.*sh|curl.*\|.*sh' "$f" 2>/dev/null; then
            change "Suspicious entry found in $f (user: $u)" \
                   "User profile contains reverse shell or backdoor patterns" \
                   "Commented out suspicious lines in $f" \
                   "grep suspicious $f — should return nothing"
            sed -i '/nc -\|\/dev\/tcp\|mkfifo\|bash -i\|python -c\|perl -e\|ruby -e\|netcat\|reverse\|backdoor\|wget.*|.*sh\|curl.*|.*sh/s/^/# DISABLED: /' "$f"
        fi
    done
done

subheader "Command History"

run_cmd "Root bash history" "cat /root/.bash_history 2>/dev/null || echo 'No root history'"
run_cmd "User bash histories" "for u in \$(awk -F: '\$3 >= 1000 && \$3 < 65534 {print \$1}' /etc/passwd); do echo \"=== \$u history ===\"; cat /home/\$u/.bash_history 2>/dev/null; echo; done"

# ============================================================
# 10. NETWORK CONFIGURATION + FIXES
# ============================================================

header "10. NETWORK CONFIGURATION + FIXES"

subheader "Network Interfaces"

run_cmd "IP addresses" "ip addr"
run_cmd "Routing table" "ip route"
run_cmd "DNS config" "cat /etc/resolv.conf 2>/dev/null"
run_cmd "Hosts file" "cat /etc/hosts"

subheader "Network Security Settings"

run_cmd "IP forwarding status" "cat /proc/sys/net/ipv4/ip_forward"
run_cmd "IP forwarding (sysctl)" "sysctl net.ipv4.ip_forward 2>/dev/null"
run_cmd "Accept redirects" "sysctl net.ipv4.conf.all.accept_redirects 2>/dev/null"
run_cmd "Accept source route" "sysctl net.ipv4.conf.all.accept_source_route 2>/dev/null"
run_cmd "Reverse path filter" "sysctl net.ipv4.conf.all.rp_filter 2>/dev/null"
run_cmd "Log martians" "sysctl net.ipv4.conf.all.log_martians 2>/dev/null"
run_cmd "Full sysctl.conf" "cat /etc/sysctl.conf 2>/dev/null"

# --- FIX: Disable IP forwarding ---
ip_forward=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)
if [[ "$ip_forward" == "1" ]]; then
    change "IP forwarding is enabled" \
           "IP forwarding should be disabled unless the machine is a router" \
           "Set net.ipv4.ip_forward = 0 in /etc/sysctl.conf; sysctl -p" \
           "cat /proc/sys/net/ipv4/ip_forward — should be 0"

    # Add or update in sysctl.conf
    if grep -q 'net.ipv4.ip_forward' /etc/sysctl.conf 2>/dev/null; then
        sed -i 's/^#*net.ipv4.ip_forward.*/net.ipv4.ip_forward = 0/' /etc/sysctl.conf
    else
        echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
    fi
    sysctl -w net.ipv4.ip_forward=0 2>/dev/null
fi

# --- FIX: Disable accept redirects ---
accept_redirects=$(sysctl net.ipv4.conf.all.accept_redirects 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
if [[ "$accept_redirects" == "1" ]]; then
    change "ICMP redirect acceptance is enabled" \
           "Redirects can be used for MITM attacks" \
           "Set net.ipv4.conf.all.accept_redirects = 0 in /etc/sysctl.conf; sysctl -p" \
           "sysctl net.ipv4.conf.all.accept_redirects — should be 0"

    if grep -q 'net.ipv4.conf.all.accept_redirects' /etc/sysctl.conf 2>/dev/null; then
        sed -i 's/^#*net.ipv4.conf.all.accept_redirects.*/net.ipv4.conf.all.accept_redirects = 0/' /etc/sysctl.conf
    else
        echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
    fi
    sysctl -w net.ipv4.conf.all.accept_redirects=0 2>/dev/null
fi

# --- FIX: Disable accept source route ---
accept_source_route=$(sysctl net.ipv4.conf.all.accept_source_route 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
if [[ "$accept_source_route" == "1" ]]; then
    change "Source routing is enabled" \
           "Source routing can be used for packet spoofing" \
           "Set net.ipv4.conf.all.accept_source_route = 0 in /etc/sysctl.conf; sysctl -p" \
           "sysctl net.ipv4.conf.all.accept_source_route — should be 0"

    if grep -q 'net.ipv4.conf.all.accept_source_route' /etc/sysctl.conf 2>/dev/null; then
        sed -i 's/^#*net.ipv4.conf.all.accept_source_route.*/net.ipv4.conf.all.accept_source_route = 0/' /etc/sysctl.conf
    else
        echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
    fi
    sysctl -w net.ipv4.conf.all.accept_source_route=0 2>/dev/null
fi

sysctl -p 2>/dev/null

# ============================================================
# 11. AUTHENTICATION POLICY + FIXES
# ============================================================

header "11. AUTHENTICATION POLICY + FIXES"

subheader "Password Policy"

run_cmd "login.defs password settings" "grep -E 'PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE|ENCRYPT_METHOD' /etc/login.defs"
run_cmd "pwquality.conf" "cat /etc/security/pwquality.conf 2>/dev/null || echo 'No pwquality.conf'"

# --- FIX: Set global password policy in login.defs ---
login_defs_modified=false

if ! grep -q '^PASS_MAX_DAYS   90' /etc/login.defs 2>/dev/null; then
    change "PASS_MAX_DAYS not set to 90 in /etc/login.defs" \
           "Passwords should expire after 90 days" \
           "Set PASS_MAX_DAYS 90 in /etc/login.defs" \
           "grep PASS_MAX_DAYS /etc/login.defs"
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs 2>/dev/null
    login_defs_modified=true
fi

if ! grep -q '^PASS_MIN_DAYS   1' /etc/login.defs 2>/dev/null; then
    change "PASS_MIN_DAYS not set to 1 in /etc/login.defs" \
           "Minimum days between password changes should be 1" \
           "Set PASS_MIN_DAYS 1 in /etc/login.defs" \
           "grep PASS_MIN_DAYS /etc/login.defs"
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs 2>/dev/null
    login_defs_modified=true
fi

if ! grep -q '^PASS_WARN_AGE   7' /etc/login.defs 2>/dev/null; then
    change "PASS_WARN_AGE not set to 7 in /etc/login.defs" \
           "Users should be warned 7 days before password expiry" \
           "Set PASS_WARN_AGE 7 in /etc/login.defs" \
           "grep PASS_WARN_AGE /etc/login.defs"
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs 2>/dev/null
    login_defs_modified=true
fi

# --- FIX: Set password quality in pwquality.conf ---
PWQUALITY_FILE="/etc/security/pwquality.conf"
pwquality_modified=false

if [[ ! -f "$PWQUALITY_FILE" ]] || ! grep -q '^minlen' "$PWQUALITY_FILE" 2>/dev/null; then
    change "Password minimum length not configured" \
           "Passwords should be at least 8 characters" \
           "Set minlen = 8 in $PWQUALITY_FILE" \
           "grep minlen $PWQUALITY_FILE"
    echo "minlen = 8" >> "$PWQUALITY_FILE" 2>/dev/null
    pwquality_modified=true
fi

if [[ ! -f "$PWQUALITY_FILE" ]] || ! grep -q '^minclass' "$PWQUALITY_FILE" 2>/dev/null; then
    change "Password minclass not configured" \
           "Passwords should use at least 3 character classes" \
           "Set minclass = 3 in $PWQUALITY_FILE" \
           "grep minclass $PWQUALITY_FILE"
    echo "minclass = 3" >> "$PWQUALITY_FILE" 2>/dev/null
    pwquality_modified=true
fi

# --- FIX: Ensure PAM enforces pwquality ---
PAM_COMMON="/etc/pam.d/common-password"
if [[ -f "$PAM_COMMON" ]]; then
    if ! grep -q 'pam_pwquality.so' "$PAM_COMMON" 2>/dev/null; then
        change "PAM does not enforce password quality (pam_pwquality.so missing)" \
               "Password quality should be enforced through PAM" \
               "Added pam_pwquality.so to $PAM_COMMON" \
               "grep pam_pwquality $PAM_COMMON"
        # Insert before the pam_unix.so line
        sed -i '/pam_unix.so/i password requisite pam_pwquality.so retry=3' "$PAM_COMMON" 2>/dev/null
    fi

    # Ensure sha512 is used
    if ! grep -q 'sha512' "$PAM_COMMON" 2>/dev/null; then
        change "PAM not using SHA512 for password hashing" \
               "Passwords should be hashed with SHA512" \
           "Added sha512 to pam_unix.so line in $PAM_COMMON" \
           "grep sha512 $PAM_COMMON"
        sed -i 's/\(password.*pam_unix.so.*\)/\1 sha512/' "$PAM_COMMON" 2>/dev/null
    fi
fi

run_cmd "login.defs after fixes" "grep -E 'PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE' /etc/login.defs"
run_cmd "pwquality.conf after fixes" "cat /etc/security/pwquality.conf 2>/dev/null"
run_cmd "common-password after fixes" "cat /etc/pam.d/common-password 2>/dev/null"

subheader "PAM Configuration"

run_cmd "common-auth" "cat /etc/pam.d/common-auth 2>/dev/null"
run_cmd "common-account" "cat /etc/pam.d/common-account 2>/dev/null"
run_cmd "common-session" "cat /etc/pam.d/common-session 2>/dev/null"

# ============================================================
# 12. UPDATES & PACKAGES
# ============================================================

header "12. UPDATES & PACKAGES"

subheader "Installed Packages"

run_cmd "Total installed packages" "dpkg -l | wc -l"
run_cmd "Recently installed packages" "ls -lt /var/lib/dpkg/info/*.list 2>/dev/null | head -30"

subheader "Available Updates"

run_cmd "Update check" "apt update 2>&1"
run_cmd "Upgradable packages" "apt list --upgradable 2>/dev/null"

# --- FIX: Install updates ---
upgradable=$(apt list --upgradable 2>/dev/null | grep -c upgradable)
if [[ "$upgradable" -gt 0 ]]; then
    change "$upgradable packages have updates available" \
           "System should be fully patched" \
           "apt upgrade -y" \
           "apt list --upgradable — should return nothing"
    apt upgrade -y 2>/dev/null
    apt autoremove -y 2>/dev/null
fi

run_cmd "Upgradable after update" "apt list --upgradable 2>/dev/null"

# ============================================================
# 13. LOGS & FORENSIC EVIDENCE
# ============================================================

header "13. LOGS & FORENSIC EVIDENCE"

subheader "Authentication Log"

run_cmd "Recent auth log" "tail -100 /var/log/auth.log 2>/dev/null || echo 'auth.log not found'"
run_cmd "Failed login attempts" "grep -i 'failed\|invalid\|error' /var/log/auth.log 2>/dev/null | tail -30 || echo 'No auth.log or no failed attempts'"
run_cmd "Sudo usage in logs" "grep -i 'sudo' /var/log/auth.log 2>/dev/null | tail -30 || echo 'No sudo entries found'"

subheader "System Log"

run_cmd "Recent syslog" "tail -100 /var/log/syslog 2>/dev/null || echo 'syslog not found'"

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

# NOTE: Forensic evidence is preserved — no deletions in this section

# ============================================================
# 14. BROWSER SETTINGS
# ============================================================

header "14. BROWSER SETTINGS"

run_cmd "Firefox installed?" "dpkg -l | grep firefox || echo 'Firefox not installed'"
run_cmd "Firefox syspref.js" "cat /etc/firefox/syspref.js 2>/dev/null || echo 'No syspref.js'"

# --- FIX: Disable Firefox auto-update if present ---
if [[ -d "/etc/firefox" ]]; then
    if [[ ! -f "/etc/firefox/syspref.js" ]] || ! grep -q 'app.update.enabled' /etc/firefox/syspref.js 2>/dev/null; then
        change "Firefox auto-update not disabled" \
               "Auto-update can cause issues in competition environment" \
               "Added lockPref app.update.enabled false to syspref.js" \
               "grep app.update /etc/firefox/syspref.js"
        echo 'lockPref("app.update.enabled", false);' >> /etc/firefox/syspref.js 2>/dev/null
    fi
fi

run_cmd "Firefox auto-update setting after fix" "grep -r 'app.update' /etc/firefox/ 2>/dev/null || echo 'No Firefox config found'"

# ============================================================
# 15. FINAL VERIFICATION
# ============================================================

header "15. FINAL VERIFICATION"

subheader "Users & Access"

run_cmd "Human accounts after fixes" "awk -F: '\$3 >= 1000 && \$3 < 65534 {print \$1, \$3, \$6, \$7}' /etc/passwd"
run_cmd "UID 0 accounts (should be root only)" "awk -F: '\$3 == 0 {print \$1}' /etc/passwd"
run_cmd "sudo group members" "getent group sudo"
run_cmd "admin group members" "getent group admin 2>/dev/null || echo 'admin group not found'"
run_cmd "Password status for all users" "for u in \$(awk -F: '\$3 >= 1000 && \$3 < 65534 {print \$1}' /etc/passwd); do echo -n \"\$u: \"; passwd -S \$u 2>/dev/null; done"

subheader "Services & Ports"

run_cmd "Running services after fixes" "systemctl --type=service --state=running --no-pager"
run_cmd "Listening ports after fixes" "ss -tulpn"

if [[ -n "$REQ_SERVICES" ]]; then
    for svc in $REQ_SERVICES; do
        run_cmd "Required service: $svc" "systemctl status $svc 2>/dev/null || echo 'Not found'"
    done
fi

subheader "Firewall"

run_cmd "UFW status" "ufw status verbose 2>/dev/null || echo 'UFW not available'"

subheader "SSH"

run_cmd "SSH config validation" "/usr/sbin/sshd -t 2>&1 || echo 'sshd not installed'"
run_cmd "Effective SSH settings" "/usr/sbin/sshd -T 2>/dev/null | grep -E 'permitrootlogin|permitemptypasswords|passwordauthentication|maxauthtries' || echo 'Could not check'"

subheader "File Permissions"

run_cmd "Critical file permissions" "ls -la /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers /etc/crontab /etc/ssh/sshd_config 2>/dev/null"
run_cmd "SUID files after fixes" "find / -perm /4000 -type f 2>/dev/null"
run_cmd "World-writable files after fixes" "find / -perm -0002 -type f 2>/dev/null | grep -v '/proc\|/sys\|/dev\|/run\|/tmp' | head -20"

subheader "Sudoers"

run_cmd "Sudoers validation" "visudo -c"
run_cmd "NOPASSWD entries after fixes" "grep -rn 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null || echo 'No NOPASSWD entries found'"

subheader "Cron & Persistence"

run_cmd "System crontab after fixes" "cat /etc/crontab 2>/dev/null"
run_cmd "cron.d after fixes" "ls -la /etc/cron.d/ 2>/dev/null"
run_cmd "User crontabs after fixes" "ls -la /var/spool/cron/crontabs/ 2>/dev/null || echo 'No user crontabs'"
run_cmd "Enabled services after fixes" "systemctl list-unit-files --state=enabled --no-pager | head -30"

subheader "Network"

run_cmd "IP forwarding after fixes" "cat /proc/sys/net/ipv4/ip_forward"
run_cmd "Accept redirects after fixes" "sysctl net.ipv4.conf.all.accept_redirects 2>/dev/null"

subheader "Password Policy"

run_cmd "login.defs after fixes" "grep -E 'PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE' /etc/login.defs"
run_cmd "pwquality after fixes" "cat /etc/security/pwquality.conf 2>/dev/null"
run_cmd "PAM common-password after fixes" "cat /etc/pam.d/common-password 2>/dev/null"

# ============================================================
# SUMMARY
# ============================================================

header "AUDIT + FIX COMPLETE"

echo "Audit and auto-fix complete." | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"
echo "Full report:     $REPORT_FILE" | tee -a "$REPORT_FILE"
echo "Change log:      $CHANGE_LOG" | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"
echo "Review the change log to see all fixes applied." | tee -a "$REPORT_FILE"
echo "Review the report for any [MANUAL REVIEW NEEDED] items." | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"

# Count changes
fix_count=$(grep -c '^\[FINDING\]' "$CHANGE_LOG" 2>/dev/null || echo 0)
manual_count=$(grep -c '^\[MANUAL\]' "$CHANGE_LOG" 2>/dev/null || echo 0)

echo "Fixes applied:        $fix_count" | tee -a "$REPORT_FILE"
echo "Manual review needed: $manual_count" | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"
echo "Items needing manual review:" | tee -a "$REPORT_FILE"
grep '^\[MANUAL\]' "$CHANGE_LOG" 2>/dev/null | sed 's/^\[MANUAL\]  /  /' | tee -a "$REPORT_FILE"

echo ""
echo -e "${GREEN}${BOLD}Audit + Fix complete!${NC}"
echo -e "${YELLOW}Report:     ${REPORT_FILE}${NC}"
echo -e "${YELLOW}Change log: ${CHANGE_LOG}${NC}"
echo ""
echo "Review the change log for all fixes applied."
echo "Review the report for any items needing manual attention."
