#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Install ucabled on a non-NixOS systemd distribution.
#
# NixOS is covered by nixosModules.ucabled; this script is only for other
# distributions.  It must run as root and assumes systemd.
#
# Usage:
#   cargo build --release            # as your normal user, first
#   sudo ./install.sh [--prefix DIR]
#   sudo ./install.sh --uninstall [--prefix DIR]
#
# The installation prefix defaults to /usr/local and can be changed with
# --prefix or the PREFIX environment variable.  The system paths below have
# sane defaults and can be overridden for distributions that differ.

set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"

# System paths (override via the environment for unusual distributions).
UDEV_DIR="${UDEV_DIR:-/etc/udev/rules.d}"
MODULES_LOAD_DIR="${MODULES_LOAD_DIR:-/etc/modules-load.d}"
DBUS_DIR="${DBUS_DIR:-/etc/dbus-1/system.d}"
POLKIT_ACTIONS_DIR="${POLKIT_ACTIONS_DIR:-/usr/share/polkit-1/actions}"
SYSTEMD_SYSTEM_DIR="${SYSTEMD_SYSTEM_DIR:-/etc/systemd/system}"
SYSTEMD_USER_DIR="${SYSTEMD_USER_DIR:-/usr/lib/systemd/user}"

BINARIES=(ucabled ucable-agent ucable-agent-helper)
UNINSTALL=0

die() {
    printf 'install.sh: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
Install ucabled on a non-NixOS systemd distribution.

Usage:
  cargo build --release            # as your normal user, first
  sudo ./install.sh [--prefix DIR]
  sudo ./install.sh --uninstall [--prefix DIR]

The installation prefix defaults to /usr/local and can be changed with
--prefix or the PREFIX environment variable.  The system paths can be
overridden with UDEV_DIR, MODULES_LOAD_DIR, DBUS_DIR, POLKIT_ACTIONS_DIR, SYSTEMD_SYSTEM_DIR and SYSTEMD_USER_DIR.
EOF
}

while (($#)); do
    case "$1" in
        --prefix) PREFIX="${2:?--prefix needs a directory}"; shift 2 ;;
        --prefix=*) PREFIX="${1#--prefix=}"; shift ;;
        --uninstall) UNINSTALL=1; shift ;;
        -h | --help) usage; exit 0 ;;
        *) die "unknown argument: $1 (try --help)" ;;
    esac
done

# The script lives at the repository root; resolve everything relative to it
# so it works from any working directory.
ROOT="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
DIST="$ROOT/dist"
RELEASE_DIR="$ROOT/target/release"
BIN_DIR="$PREFIX/bin"

[[ $EUID -eq 0 ]] || die "must run as root (e.g. sudo $0)"
[[ -d "$DIST" ]] || die "dist/ not found next to the script; run it from the repository"
if [[ -e /etc/NIXOS || -e /run/current-system ]]; then
    die "NixOS detected; use nixosModules.ucabled instead of this script"
fi
command -v systemctl >/dev/null || die "systemd is required"
command -v udevadm >/dev/null || die "udev is required"

nologin="$(command -v nologin || true)"
[[ -n "$nologin" ]] || nologin=/usr/sbin/nologin

udev_reload() {
    udevadm control --reload-rules
    udevadm trigger --subsystem-match=misc
}

# Copy a unit file, rewriting the baked-in /usr/local/bin to the chosen
# prefix (a plain bash substitution, so '&' in the path stays literal).
install_unit() {
    local src="$1" dest="$2" content bin
    content="$(<"$src")"
    # '&' is special in the replacement, so escape it.
    bin="${BIN_DIR//&/\\&}"
    printf '%s\n' "${content//\/usr\/local\/bin/$bin}" >"$dest"
    chmod 0644 "$dest"
}

# Copy the udev rule, baking in the setfacl path found on this system.  The
# rule is otherwise installed verbatim, and distributions disagree on where
# setfacl lives, so a hardcoded /usr/bin/setfacl silently fails elsewhere and
# leaves the daemon unable to open /dev/uhid.
install_udev_rule() {
    local src="$1" dest="$2" content acl
    content="$(<"$src")"
    # '&' is special in the replacement, so escape it.
    acl="${SETFACL//&/\\&}"
    printf '%s\n' "${content//\/usr\/bin\/setfacl/$acl}" >"$dest"
    chmod 0644 "$dest"
}

if ((UNINSTALL)); then
    systemctl disable --now ucabled.service 2>/dev/null || true
    systemctl --global disable ucable-agent.service 2>/dev/null || true

    rm -f "$SYSTEMD_SYSTEM_DIR/ucabled.service"
    rm -f "$SYSTEMD_USER_DIR/ucable-agent.service"
    rm -f "$UDEV_DIR/90-ucabled.rules"
    rm -f "$MODULES_LOAD_DIR/ucabled.conf"
    rm -f "$DBUS_DIR/org.ucabled.conf"
    rm -f "$POLKIT_ACTIONS_DIR/org.ucabled.policy"
    # Installed by versions that shipped a BlueZ polkit rule.
    rm -f "${POLKIT_RULES_DIR:-/etc/polkit-1/rules.d}/50-ucabled-bluez.rules"
    for b in "${BINARIES[@]}"; do
        rm -f "$BIN_DIR/$b"
    done
    for po in "$ROOT"/po/*.po; do
        [[ -e "$po" ]] || continue
        lang="$(basename "$po" .po)"
        rm -f "$PREFIX/share/locale/$lang/LC_MESSAGES/ucable.mo"
        # Installed by versions before the domain was renamed to "ucable".
        rm -f "$PREFIX/share/locale/$lang/LC_MESSAGES/ucable-agent-helper-gtk.mo"
    done
    rm -f "$PREFIX/share/man/man1/ucabled.1" \
        "$PREFIX/share/man/man1/ucable-agent.1" \
        "$PREFIX/share/man/man1/ucable-agent-helper.1"
    rm -f "$PREFIX/share/bash-completion/completions/ucabled" \
        "$PREFIX/share/bash-completion/completions/ucable-agent-helper"
    rm -f "$PREFIX/share/zsh/site-functions/_ucabled" \
        "$PREFIX/share/zsh/site-functions/_ucable-agent-helper"
    rm -f "$PREFIX/share/fish/vendor_completions.d/ucabled.fish" \
        "$PREFIX/share/fish/vendor_completions.d/ucable-agent-helper.fish"
    rm -rf "$PREFIX/share/gnome-shell/extensions/ucable-gnome-agent@fuzy.me"

    systemctl daemon-reload || true
    systemctl reload dbus 2>/dev/null || true
    udev_reload || true

    cat >&2 <<EOF
Removed ucabled from $PREFIX.

The ucabled user/group and the /dev/uhid ACL were kept.  To remove them:

    userdel ucabled
    groupdel ucabled
    setfacl -x u:ucabled /dev/uhid

The ACL also disappears on the next reboot, or after
'udevadm trigger /sys/class/misc/uhid' now that the rule is gone.

The long-term caBLE identity key was kept at
/var/lib/ucabled/identity.key.  Delete it (and the directory) only if
you will not reinstall: phones will no longer recognise this machine
once a different key is generated.
EOF
    exit 0
fi

missing=()
for b in "${BINARIES[@]}"; do
    [[ -x "$RELEASE_DIR/$b" ]] || missing+=("$b")
done
if ((${#missing[@]})); then
    die "missing built binaries in $RELEASE_DIR: ${missing[*]}
build them first as your normal user with:  cargo build --release"
fi

SETFACL="$(command -v setfacl)" ||
    die 'setfacl not found; install the "acl" package (the udev rule needs it)'

# Dedicated service account; the human user only needs the hidraw node.
getent group ucabled >/dev/null || groupadd --system ucabled
getent passwd ucabled >/dev/null ||
    useradd --system --gid ucabled --no-create-home \
        --home-dir /nonexistent --shell "$nologin" ucabled

# -s strips the symbol table; cargo's release profile leaves it in.
install -d -m 0755 "$BIN_DIR"
for b in "${BINARIES[@]}"; do
    install -s -m 0755 -o root -g root "$RELEASE_DIR/$b" "$BIN_DIR/$b"
done

# Manual pages and shell completions.
install -d -m 0755 "$PREFIX/share/man/man1"
for m in "${BINARIES[@]}"; do
    install -m 0644 -o root -g root "$DIST/man/$m.1" "$PREFIX/share/man/man1/$m.1"
done
install -d -m 0755 "$PREFIX/share/bash-completion/completions"
install -m 0644 -o root -g root "$DIST/completions/ucabled.bash" \
    "$PREFIX/share/bash-completion/completions/ucabled"
install -m 0644 -o root -g root "$DIST/completions/ucable-agent-helper.bash" \
    "$PREFIX/share/bash-completion/completions/ucable-agent-helper"
install -d -m 0755 "$PREFIX/share/zsh/site-functions"
install -m 0644 -o root -g root "$DIST/completions/_ucabled" \
    "$PREFIX/share/zsh/site-functions/_ucabled"
install -m 0644 -o root -g root "$DIST/completions/_ucable-agent-helper" \
    "$PREFIX/share/zsh/site-functions/_ucable-agent-helper"
install -d -m 0755 "$PREFIX/share/fish/vendor_completions.d"
install -m 0644 -o root -g root "$DIST/completions/ucabled.fish" \
    "$PREFIX/share/fish/vendor_completions.d/ucabled.fish"
install -m 0644 -o root -g root "$DIST/completions/ucable-agent-helper.fish" \
    "$PREFIX/share/fish/vendor_completions.d/ucable-agent-helper.fish"

# Gettext catalogs ("ucable" domain).  The GTK4 helper looks them up
# relative to its own location (<prefix>/share/locale).
if command -v msgfmt >/dev/null; then
    for po in "$ROOT"/po/*.po; do
        [[ -e "$po" ]] || continue
        lang="$(basename "$po" .po)"
        install -d -m 0755 "$PREFIX/share/locale/$lang/LC_MESSAGES"
        msgfmt "$po" \
            -o "$PREFIX/share/locale/$lang/LC_MESSAGES/ucable.mo"
        # Left behind by versions before the domain was renamed.
        rm -f "$PREFIX/share/locale/$lang/LC_MESSAGES/ucable-agent-helper-gtk.mo"
    done
else
    printf 'warning: msgfmt not found; translations not installed (install gettext)\n' >&2
fi

# Load the uhid module now and at boot.
install -d -m 0755 "$MODULES_LOAD_DIR"
printf 'uhid\n' >"$MODULES_LOAD_DIR/ucabled.conf"
chmod 0644 "$MODULES_LOAD_DIR/ucabled.conf"
modprobe uhid || true

install -d -m 0755 "$UDEV_DIR"
install_udev_rule "$DIST/90-ucabled.rules" "$UDEV_DIR/90-ucabled.rules"

install -d -m 0755 "$DBUS_DIR"
install -m 0644 -o root -g root "$DIST/org.ucabled.conf" "$DBUS_DIR/org.ucabled.conf"

install -d -m 0755 "$POLKIT_ACTIONS_DIR"
install -m 0644 -o root -g root "$DIST/org.ucabled.policy" \
    "$POLKIT_ACTIONS_DIR/org.ucabled.policy"

# The unit files bake in the default /usr/local/bin; rewrite them for the
# chosen prefix.
install -d -m 0755 "$SYSTEMD_SYSTEM_DIR"
install_unit "$DIST/ucabled.service" "$SYSTEMD_SYSTEM_DIR/ucabled.service"

install -d -m 0755 "$SYSTEMD_USER_DIR"
install_unit "$DIST/ucable-agent.service" "$SYSTEMD_USER_DIR/ucable-agent.service"

udev_reload
systemctl daemon-reload
systemctl reload dbus 2>/dev/null || true
systemctl enable --now ucabled.service
# Global (all users) user unit, bound to the graphical session.
systemctl --global enable ucable-agent.service

cat <<EOF
ucabled installed under $PREFIX.

Log out and back in (or run 'systemctl --user start ucable-agent') so the
session agent registers and the QR window can appear.
EOF
