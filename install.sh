#!/bin/sh
# Advanced DPI Fuzzer: installs everything on the router and starts a check. In the router's SSH:
#
#   sh -c "$(curl -fsSL https://raw.githubusercontent.com/p0sixxx/advanced-dpi-fuzzer/ccr-1c98da7f-ufeaio/install.sh)"
#
# Asks which service to check. Installs Python (apk/opkg) and ADF into /opt/adf; Tachyon, firewall
# and routing stay as they are. Options (with `sh -s -- ...`): --no-check, --no-deps, --force, [service].

ADF_REPO="${ADF_REPO:-p0sixxx/advanced-dpi-fuzzer}"
ADF_REF="${ADF_REF:-ccr-1c98da7f-ufeaio}"

fail() { printf 'adf install: %s\n' "$*" >&2; exit 1; }

fetch() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL -o "$2" "$1"
	elif command -v wget >/dev/null 2>&1; then
		wget -q -O "$2" "$1"
	else
		fail "curl or wget is required"
	fi
}

main() {
	check=1
	deps=""
	while [ $# -gt 0 ]; do
		case "$1" in
			--no-check) check=0; shift ;;
			--no-deps|--force) deps="$deps $1"; shift ;;
			*) break ;;
		esac
	done

	tmp=$(mktemp -d "${TMPDIR:-/tmp}/adf-install.XXXXXX") || fail "cannot create a temporary directory"
	trap 'rm -rf "$tmp"' EXIT INT TERM
	url="https://codeload.github.com/$ADF_REPO/tar.gz/$ADF_REF"
	echo "Downloading Advanced DPI Fuzzer ($ADF_REF)..."
	fetch "$url" "$tmp/src.tgz" || fail "cannot download $url: check the router's internet access"
	mkdir "$tmp/src" "$tmp/root" "$tmp/root/bin"
	tar -xzf "$tmp/src.tgz" -C "$tmp/src" || fail "the download is damaged, run the command again"

	repo=$(echo "$tmp"/src/*)
	[ -f "$repo/packaging/adf-router.sh" ] || fail "unexpected archive layout in $url"
	mkdir "$tmp/root/lib"
	cp -R "$repo/src/adf" "$tmp/root/lib/adf"
	cp -R "$repo/agent" "$tmp/root/agent"
	cp "$repo/packaging/adf-router.sh" "$tmp/root/bin/adf-router"
	sed -n 's/^__version__ = "\(.*\)"$/\1/p' "$repo/src/adf/__init__.py" > "$tmp/root/VERSION"

	# shellcheck disable=SC2086  # $deps is a list of flags
	sh "$tmp/root/bin/adf-router" __install "$tmp/root" $deps || exit 1
	rm -rf "$tmp"
	trap - EXIT INT TERM

	[ "$check" = 1 ] || return 0
	router="${ADF_BIN_DIR:-/usr/bin}/adf-router"
	if [ $# -gt 0 ] || ( : <"${ADF_TTY:-/dev/tty}" ) 2>/dev/null; then
		exec "$router" check "$@"
	fi
	echo "No terminal here: start the check with  adf-router check"
}

# Everything is inside main, so a download cut in half does nothing.
main "$@"
