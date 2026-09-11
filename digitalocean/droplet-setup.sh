#!/bin/bash
set -euo pipefail

# Report the failing line rather than exiting silently under set -e.
trap 'echo "Error: ${BASH_SOURCE[0]}:${LINENO}: command failed with status $?" >&2' ERR

readonly DEFAULT_PACKAGES=(
    git tmux vim curl ca-certificates ripgrep jq unzip
)
# Kept separate so -n can drop it: build-essential is ~200MB, which matters on
# the smallest droplets but is the difference between "can build anything" and
# a cryptic compile failure later.
readonly BUILD_PACKAGES=(build-essential)

MINIMAL=0
DRY_RUN=0
HARDEN_SSH=0
SWAP_SIZE=""
NEW_HOSTNAME=""

usage() {
    cat <<EOF
Usage: $(basename "$0") [-n] [-s SIZE] [-H HOSTNAME] [-S] [-d] USERNAME PUBLIC_KEY_FILE

Provision a new DigitalOcean droplet with a sudo-enabled user and SSH access.

Arguments:
  USERNAME         Name of the user account to create
  PUBLIC_KEY_FILE  Path to the SSH public key file to authorize (may hold several keys)

Options:
  -n           Minimal package set (skip build-essential)
  -s SIZE      Swap file size, e.g. 2G. Default: 2G when RAM is under 2GB, else none
  -H HOSTNAME  Set the system hostname
  -S           Harden sshd (disable password authentication). See below
  -d           Dry run: print what would change without changing it
  -h           Show this help

Safe to re-run: an existing user is reused and keys already present in
authorized_keys are not added twice.

SSH hardening is opt-in for a reason. Run without -S first, confirm you can
"ssh USERNAME@host" and run "sudo -n true" from another terminal, then re-run
with -S. Disabling password authentication in the same pass that installs an
unverified key is the one mistake here that cannot be undone remotely.

Must be run as root.
EOF
}

log()  { printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
warn() { printf '[%s] WARNING: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }
die()  { printf '[%s] ERROR: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; exit 1; }

# Wraps commands for -d. Redirections cannot be intercepted this way, so file
# writes carry their own dry-run guards.
run() {
    if [[ $DRY_RUN -eq 1 ]]; then
        printf 'DRY-RUN:'
        printf ' %q' "$@"
        printf '\n'
        return 0
    fi
    "$@"
}

while getopts ':ns:H:Sdh' opt; do
    case "$opt" in
        n) MINIMAL=1 ;;
        s) SWAP_SIZE="$OPTARG" ;;
        H) NEW_HOSTNAME="$OPTARG" ;;
        S) HARDEN_SSH=1 ;;
        d) DRY_RUN=1 ;;
        h) usage; exit 0 ;;
        :) usage >&2; die "Option -$OPTARG requires an argument." ;;
        ?) usage >&2; die "Unknown option: -$OPTARG" ;;
    esac
done
shift $((OPTIND - 1))

if [[ $# -ne 2 ]]; then
    usage >&2
    exit 1
fi

USERNAME="$1"
PUBLIC_KEY_FILE="$2"

if [[ $EUID -ne 0 ]]; then
    die "This script must be run as root."
fi

if [[ ! -r "$PUBLIC_KEY_FILE" ]]; then
    die "Public key file '$PUBLIC_KEY_FILE' does not exist or is not readable."
fi

# ssh-keygen parses both public and private keys, so it alone would accept a
# private key handed over by mistake. Require a public key prefix as well.
validate_key() {
    local key="$1" tmp
    if [[ "$key" != ssh-* && "$key" != ecdsa-* && "$key" != sk-* ]]; then
        return 1
    fi
    tmp="$(mktemp)"
    printf '%s\n' "$key" > "$tmp"
    if ! ssh-keygen -l -f "$tmp" >/dev/null 2>&1; then
        rm -f "$tmp"
        return 1
    fi
    rm -f "$tmp"
}

# Command substitution strips trailing newlines, so a file that already ends in
# a newline yields an empty string here. A non-empty result means the last line
# is unterminated and a separator is needed before appending.
ensure_trailing_newline() {
    local file="$1"
    if [[ -s "$file" ]] && [[ -n "$(tail -c 1 "$file")" ]]; then
        printf '\n' >> "$file"
    fi
}

# Validate every key before touching the system, so a bad file fails before any
# changes are made.
key_count=0
while IFS= read -r key || [[ -n "$key" ]]; do
    key="${key%$'\r'}"
    [[ -z "$key" || "$key" == \#* ]] && continue
    validate_key "$key" \
        || die "Not an SSH public key (expected a line beginning with ssh-, ecdsa-, or sk-): ${key:0:40}..."
    key_count=$((key_count + 1))
done < "$PUBLIC_KEY_FILE"

if [[ $key_count -eq 0 ]]; then
    die "No SSH public keys found in '$PUBLIC_KEY_FILE'."
fi
log "Validated $key_count key(s) from '$PUBLIC_KEY_FILE'."

# Fail early on an image without the sudo group rather than midway through,
# which would leave the user created but no SSH access configured.
getent group sudo >/dev/null || die "Group 'sudo' does not exist on this system."

# Create user, reusing the account if this is a re-run
if id -u "$USERNAME" >/dev/null 2>&1; then
    log "User '$USERNAME' already exists; reusing it."
else
    run adduser --disabled-password --gecos "" "$USERNAME"
fi
run usermod -aG sudo "$USERNAME"

# Read the home from passwd rather than assuming /home/$USERNAME: a reused
# account may have a home elsewhere, and writing keys to the wrong path would
# report success while leaving no way in.
if [[ $DRY_RUN -eq 1 ]] && ! id -u "$USERNAME" >/dev/null 2>&1; then
    USER_HOME="/home/$USERNAME"
    log "DRY-RUN: assuming home directory $USER_HOME"
else
    USER_HOME="$(getent passwd "$USERNAME" | cut -d: -f6)"
    [[ -n "$USER_HOME" && -d "$USER_HOME" ]] \
        || die "Could not determine the home directory for '$USERNAME'."
fi
AUTHORIZED_KEYS="$USER_HOME/.ssh/authorized_keys"

# sshd StrictModes rejects keys when the home directory itself is wrong-owned or
# group-writable, so fix the home directory, not just .ssh.
run chown "$USERNAME:$USERNAME" "$USER_HOME"
run chmod go-w "$USER_HOME"
run install -d -m 700 -o "$USERNAME" -g "$USERNAME" "$USER_HOME/.ssh"

if [[ $DRY_RUN -eq 1 ]]; then
    log "DRY-RUN: would install $key_count key(s) into $AUTHORIZED_KEYS"
else
    touch "$AUTHORIZED_KEYS"
    # Install each key separately. grep -F treats a multi-line pattern as
    # alternatives rather than a literal match, so comparing the whole file at
    # once would report a match when only one of several keys was present and
    # silently drop the rest.
    while IFS= read -r key || [[ -n "$key" ]]; do
        key="${key%$'\r'}"
        [[ -z "$key" || "$key" == \#* ]] && continue
        if grep -qxF -- "$key" "$AUTHORIZED_KEYS"; then
            log "Key already authorized: ${key##* }"
            continue
        fi
        ensure_trailing_newline "$AUTHORIZED_KEYS"
        printf '%s\n' "$key" >> "$AUTHORIZED_KEYS"
        log "Authorized key: ${key##* }"
    done < "$PUBLIC_KEY_FILE"

    chmod 600 "$AUTHORIZED_KEYS"
    chown "$USERNAME:$USERNAME" "$AUTHORIZED_KEYS"
fi

# adduser --disabled-password leaves '!' in the shadow password field, so the
# account cannot authenticate to sudo with a password at all. Without this the
# sudo group membership above is useless. The SSH key is the real authentication
# boundary on a key-only box.
SUDOERS_FILE="/etc/sudoers.d/90-${USERNAME}"
if [[ $DRY_RUN -eq 1 ]]; then
    log "DRY-RUN: would install $SUDOERS_FILE granting passwordless sudo"
else
    # Validate before installing: a malformed sudoers file breaks sudo entirely.
    tmp_sudoers="$(mktemp)"
    printf '%s ALL=(ALL) NOPASSWD:ALL\n' "$USERNAME" > "$tmp_sudoers"
    if ! visudo -cf "$tmp_sudoers" >/dev/null; then
        rm -f "$tmp_sudoers"
        die "Generated sudoers file is invalid; refusing to install it."
    fi
    # Mode 440 and root ownership are mandatory: sudo ignores files that are
    # group or world writable. The filename must contain no dot, which
    # sudo's #includedir skips.
    install -m 440 -o root -g root "$tmp_sudoers" "$SUDOERS_FILE"
    rm -f "$tmp_sudoers"
    log "Granted passwordless sudo via $SUDOERS_FILE."
fi

# Install packages. cloud-init and unattended-upgrades hold the dpkg lock for
# the first minutes of a droplet's life, so lean on apt's own lock timeout
# rather than failing the whole run. Retries cover transient mirror errors and
# force-confold keeps a config prompt from blocking a non-tty run.
export DEBIAN_FRONTEND=noninteractive
APT_OPTS=(
    -o DPkg::Lock::Timeout=300
    -o Acquire::Retries=3
    -o Dpkg::Options::=--force-confold
)

packages=("${DEFAULT_PACKAGES[@]}" unattended-upgrades)
if [[ $MINIMAL -eq 0 ]]; then
    packages+=("${BUILD_PACKAGES[@]}")
fi

log "Updating package lists..."
run apt-get "${APT_OPTS[@]}" update
log "Installing: ${packages[*]}"
run apt-get "${APT_OPTS[@]}" install -y --no-install-recommends "${packages[@]}"

# Enabling is not guaranteed even when the package ships with the image.
run dpkg-reconfigure -f noninteractive unattended-upgrades

# Deliberately no fail2ban. With password and keyboard-interactive auth off
# there is no credential to brute force, so it would buy only log-noise
# reduction while adding a daemon, a Python dependency, and a real risk of
# banning yourself over a mistyped key.

# Swap: small droplets OOM during compiles. Skip when swap already exists.
current_swap="$(swapon --show 2>/dev/null || true)"
total_ram_mb="$(free -m 2>/dev/null | awk '/^Mem:/{print $2}' || echo 0)"
if [[ -n "$SWAP_SIZE" ]] || { [[ -z "$current_swap" ]] && [[ "${total_ram_mb:-0}" -lt 2048 ]]; }; then
    if [[ -n "$current_swap" ]]; then
        log "Swap is already configured; leaving it as is."
    else
        swap_size="${SWAP_SIZE:-2G}"
        log "Creating a $swap_size swap file..."
        if [[ $DRY_RUN -eq 1 ]]; then
            log "DRY-RUN: would create /swapfile ($swap_size) and add it to /etc/fstab"
        else
            # On some filesystems fallocate produces a file mkswap rejects.
            fallocate -l "$swap_size" /swapfile \
                || dd if=/dev/zero of=/swapfile bs=1M count=2048 status=none
            chmod 600 /swapfile
            mkswap /swapfile >/dev/null
            swapon /swapfile
            grep -qxF '/swapfile none swap sw 0 0' /etc/fstab \
                || printf '/swapfile none swap sw 0 0\n' >> /etc/fstab
            # Persist so it survives a reboot.
            printf 'vm.swappiness=10\n' > /etc/sysctl.d/99-swappiness.conf
            sysctl -q vm.swappiness=10
        fi
    fi
fi

# Hostname. Without the matching /etc/hosts entry sudo warns "unable to resolve
# host" on every invocation.
if [[ -n "$NEW_HOSTNAME" ]]; then
    log "Setting hostname to '$NEW_HOSTNAME'..."
    run hostnamectl set-hostname "$NEW_HOSTNAME"
    if [[ $DRY_RUN -eq 1 ]]; then
        log "DRY-RUN: would map 127.0.1.1 to $NEW_HOSTNAME in /etc/hosts"
    elif ! grep -qE "^127\.0\.1\.1[[:space:]]+$NEW_HOSTNAME\$" /etc/hosts; then
        printf '127.0.1.1\t%s\n' "$NEW_HOSTNAME" >> /etc/hosts
    fi
fi

# Firewall. Allow SSH before enabling, and fall back to the port directly if the
# app profile is missing, since ufw allow OpenSSH would fail under set -e.
if ufw app info OpenSSH >/dev/null 2>&1; then
    run ufw allow OpenSSH
else
    warn "ufw OpenSSH app profile not found; allowing 22/tcp directly."
    run ufw allow 22/tcp
fi
run ufw allow 60000:61000/udp
run ufw --force enable

# SSH hardening, opt-in via -S.
if [[ $HARDEN_SSH -eq 1 ]]; then
    grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/' /etc/ssh/sshd_config \
        || die "sshd_config has no Include for sshd_config.d; a drop-in would be ignored."

    log "Hardening sshd..."
    if [[ $DRY_RUN -eq 1 ]]; then
        log "DRY-RUN: would write /etc/ssh/sshd_config.d/50-hardening.conf and reload ssh"
    else
        # PermitRootLogin stays at prohibit-password rather than no: DigitalOcean
        # installs your key for root at creation, and that is the known-good way
        # back in at exactly the moment password auth goes away.
        cat > /etc/ssh/sshd_config.d/50-hardening.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
EOF
        # A bad config makes sshd fail on reload, which locks you out.
        sshd -t || die "sshd configuration is invalid; not reloading."
        # Reload rather than restart so existing sessions survive. The service is
        # named ssh on Debian and Ubuntu, not sshd.
        systemctl reload ssh
        log "Password authentication is now disabled."
    fi
fi

log "Setup complete. User: $USERNAME"

if [[ $HARDEN_SSH -eq 0 ]]; then
    cat <<EOF

Next steps:
  1. From another terminal, confirm access:  ssh $USERNAME@<host>
  2. Confirm sudo works:                     sudo -n true
  3. Once both succeed, re-run with -S to disable password authentication.

Keep this session open until step 1 succeeds.
EOF
else
    cat <<EOF

Root login is set to prohibit-password, which keeps your DigitalOcean root key
working as a fallback. Tighten it to "no" in
/etc/ssh/sshd_config.d/50-hardening.conf once you have confirmed the
$USERNAME account.
EOF
fi

if [[ -f /var/run/reboot-required ]]; then
    log "A reboot is required to finish applying updates."
    if [[ -f /var/run/reboot-required.pkgs ]]; then
        sed 's/^/  /' /var/run/reboot-required.pkgs
    fi
fi
