# DigitalOcean

## droplet-setup.sh

Provisions a fresh Ubuntu droplet for development work: creates a sudo-enabled
user, installs SSH public keys, sets up a firewall, and installs a small set of
development packages.

```
Usage: droplet-setup.sh [-n] [-s SIZE] [-H HOSTNAME] [-S] [-d] USERNAME PUBLIC_KEY_FILE
```

| Flag | Effect |
| --- | --- |
| `-n` | Minimal package set (skips `build-essential`) |
| `-s SIZE` | Swap file size. Default: 2G when RAM is under 2GB, otherwise none |
| `-H HOSTNAME` | Set the system hostname and the matching `/etc/hosts` entry |
| `-S` | Harden sshd by disabling password authentication |
| `-d` | Dry run: print what would change without changing it |

Run as root on the droplet. Re-running is safe: an existing user is reused and
keys already present are not added twice.

### The two-step hardening flow

SSH hardening is opt-in because disabling password authentication in the same
pass that installs an unverified key is the only mistake here that cannot be
undone remotely. The recovery path is the DigitalOcean web console.

```sh
# 1. Provision. Keep this root session open.
scp droplet-setup.sh root@<host>:
ssh root@<host> './droplet-setup.sh devuser /root/id_ed25519.pub'

# 2. From a SECOND terminal, confirm both of these work:
ssh devuser@<host>
sudo -n true

# 3. Only then, harden:
ssh root@<host> './droplet-setup.sh -S devuser /root/id_ed25519.pub'
```

Step 2 is the whole point of the split. `sudo -n true` matters as much as the
login: an account created with `--disabled-password` has no password, so sudo
access depends entirely on the sudoers drop-in this script installs.

After step 3, root login is left at `prohibit-password` rather than `no`, which
keeps the key DigitalOcean installs for root working as a fallback. Tighten it
to `no` in `/etc/ssh/sshd_config.d/50-hardening.conf` once you are confident in
the new account.

### What it installs

`git`, `tmux`, `vim`, `curl`, `ca-certificates`, `ripgrep`, `jq`, `unzip`,
`unattended-upgrades`, and `build-essential` unless `-n` is given. All from
Ubuntu main, no third-party repositories.

No language runtimes, Docker, or shell changes. Those are policy decisions that
go stale and belong to a version manager or a separate script. Docker in
particular writes iptables rules that silently bypass ufw.

No fail2ban. Once password and keyboard-interactive authentication are off,
there is no credential to brute force, so it would add a daemon and a real risk
of banning yourself in exchange for quieter logs.

## Provisioning at creation time with doctl

`droplet-setup.sh` takes its username and key as arguments, but cloud-init runs
a user-data script with no arguments, no TTY, and no key file on disk yet. So
`--user-data "$(cat droplet-setup.sh)"` on its own creates a droplet that prints
usage and exits 1 without provisioning anything.

`build-user-data.sh` resolves this by wrapping the script: it embeds your public
key and the setup script into one self-contained user-data script that invokes
`droplet-setup.sh` with the arguments already filled in. Call it inline so the
whole thing stays a single command:

```sh
KEY=~/.ssh/id_ed25519_digitalocean.pub

doctl compute droplet create dev-box \
    --image ubuntu-24-04-x64 --size s-1vcpu-1gb --region nyc3 \
    --ssh-keys "$(ssh-keygen -lf "$KEY" -E md5 | awk '{sub(/^MD5:/,"",$2); print $2}')" \
    --user-data "$(./build-user-data.sh devuser "$KEY")" \
    --wait
```

Both substitutions derive from the same `$KEY`, so the key DigitalOcean installs
for root and the key the script authorizes for your user are guaranteed to
match. Deriving the fingerprint locally also means the command does not depend
on the account having exactly one key, and does not need a lookup against the
DigitalOcean API at all.

`-E md5` is required: modern `ssh-keygen` defaults to SHA256, which is not the
format DigitalOcean matches on. To see the value on its own:

```sh
ssh-keygen -lf ~/.ssh/id_ed25519_digitalocean.pub -E md5
```

The key must already be registered with the account, since `--ssh-keys` selects
from existing keys rather than uploading a new one. To check, or to see the
fingerprints DigitalOcean holds:

```sh
doctl compute ssh-key list
```

### --ssh-keys is not optional

Omitting `--ssh-keys` is the single easiest way to lock yourself out, and
doctl's own `--help` example omits it, so it is easy to inherit by accident.
With no key attached, DigitalOcean emails a random root password and leaves
password authentication enabled. Every SSH attempt then prompts for a password,
for `root` and for the new user alike, whichever key you pass to `ssh -i`.

The root key is also the fallback that lets you diagnose a failed cloud-init
run. Without it, a bad user-data script leaves the web console as the only way
back in.

### Notes

Output is logged to `/var/log/droplet-setup.log` on the droplet, since a
first-boot failure is otherwise invisible. Cloud-init's own log is at
`/var/log/cloud-init-output.log`. Note that `--wait` only waits for the droplet
to be created, not for cloud-init to finish, so it can return success while
provisioning is still running or has already failed.

User-data is capped at 64KB and is readable from the droplet's metadata
endpoint, so never embed a private key. `build-user-data.sh` refuses one.

`-S` hardens sshd during first boot. That forfeits the verify step described
above, so a wrong key file locks you out and leaves the recovery console as the
only way in. Provision without it, confirm access, then re-run with `-S`.

If you would rather keep the generated script around to inspect or re-use, the
two-step form still works:

```sh
./build-user-data.sh devuser ~/.ssh/id_ed25519_digitalocean.pub > user-data.sh
doctl compute droplet create dev-box ... --user-data-file user-data.sh --wait
```
