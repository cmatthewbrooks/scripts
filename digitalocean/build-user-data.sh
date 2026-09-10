#!/bin/bash
set -euo pipefail

# Wraps droplet-setup.sh into a single cloud-init user-data script.
#
# droplet-setup.sh takes its username and public key as arguments, but cloud-init
# runs a user-data script with no arguments and no TTY. This wrapper embeds the
# key and the script itself, then invokes it with the arguments filled in.

usage() {
    cat <<EOF
Usage: $(basename "$0") [-S] USERNAME PUBLIC_KEY_FILE [SETUP_SCRIPT]

Emit a cloud-init user-data script on stdout.

Arguments:
  USERNAME         Account to create on the droplet
  PUBLIC_KEY_FILE  Local public key file to embed (may hold several keys)
  SETUP_SCRIPT     Path to droplet-setup.sh (default: alongside this script)

Options:
  -S  Pass -S to droplet-setup.sh, hardening sshd on first boot. See the warning
      in README.md: this forfeits the verify step, so a bad key locks you out.
  -h  Show this help

Example:
  KEY=~/.ssh/id_ed25519.pub

  doctl compute droplet create dev-box \\
      --image ubuntu-24-04-x64 --size s-1vcpu-1gb --region nyc3 \\
      --ssh-keys "\$(ssh-keygen -lf "\$KEY" -E md5 | awk '{sub(/^MD5:/,"",\$2); print \$2}')" \\
      --user-data "\$($(basename "$0") devuser "\$KEY")" \\
      --wait

  Deriving both from the same key file keeps the root key and the user key in
  sync. The key must already be registered with the account: --ssh-keys selects
  an existing key rather than uploading one. List them with:
      doctl compute ssh-key list

  --ssh-keys is required. Without it DigitalOcean emails a random root password
  and leaves password authentication on, so every SSH attempt prompts for a
  password.
EOF
}

HARDEN=""
while getopts ':Sh' opt; do
    case "$opt" in
        S) HARDEN=" -S" ;;
        h) usage; exit 0 ;;
        ?) usage >&2; exit 1 ;;
    esac
done
shift $((OPTIND - 1))

if [[ $# -lt 2 || $# -gt 3 ]]; then
    usage >&2
    exit 1
fi

USERNAME="$1"
PUBLIC_KEY_FILE="$2"
SETUP_SCRIPT="${3:-$(dirname "$0")/droplet-setup.sh}"

[[ -r "$PUBLIC_KEY_FILE" ]] || { echo "Error: cannot read '$PUBLIC_KEY_FILE'." >&2; exit 1; }
[[ -r "$SETUP_SCRIPT" ]] || { echo "Error: cannot read '$SETUP_SCRIPT'." >&2; exit 1; }

# Refuse a private key here rather than embedding it in droplet metadata, which
# is readable from the droplet and stored by DigitalOcean.
if grep -q 'PRIVATE KEY' "$PUBLIC_KEY_FILE"; then
    echo "Error: '$PUBLIC_KEY_FILE' looks like a PRIVATE key. Refusing to embed it." >&2
    exit 1
fi

# Delimiters are deliberately distinct from the bare EOF markers inside
# droplet-setup.sh, and quoted so nothing is expanded while embedding.
cat <<WRAPPER_EOF
#!/bin/bash
set -euo pipefail
exec > >(tee -a /var/log/droplet-setup.log) 2>&1

cat > /root/authorized.pub <<'PUBKEY_EOF'
$(cat "$PUBLIC_KEY_FILE")
PUBKEY_EOF
chmod 600 /root/authorized.pub

cat > /root/droplet-setup.sh <<'SETUP_EOF'
$(cat "$SETUP_SCRIPT")
SETUP_EOF
chmod +x /root/droplet-setup.sh

/root/droplet-setup.sh$HARDEN $USERNAME /root/authorized.pub
WRAPPER_EOF
