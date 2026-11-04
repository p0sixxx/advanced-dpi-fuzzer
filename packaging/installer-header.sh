#!/bin/sh
# Advanced DPI Fuzzer @VERSION@ for OpenWrt: self-extracting installer.
#
#   sh adf-router-@VERSION@.sh [--no-deps]
#
# Installs Python (via apk/opkg, unless --no-deps) and ADF into /opt/adf. It does not touch
# Tachyon, firewall or routing. A .tar.gz with the program follows this header.
set -eu

PAYLOAD_LINE=@PAYLOAD_LINE@
PAYLOAD_SHA256=@PAYLOAD_SHA256@

if command -v sha256sum >/dev/null 2>&1; then
	actual=$(tail -n +"$PAYLOAD_LINE" "$0" | sha256sum | cut -d' ' -f1)
	if [ "$actual" != "$PAYLOAD_SHA256" ]; then
		echo "adf installer: the file is damaged (checksum mismatch), copy it again" >&2
		exit 1
	fi
fi

tmp=$(mktemp -d "${TMPDIR:-/tmp}/adf-install.XXXXXX")
trap 'rm -rf "$tmp"' EXIT INT TERM
tail -n +"$PAYLOAD_LINE" "$0" | tar -xzf - -C "$tmp"
sh "$tmp/bin/adf-router" __install "$tmp" "$@"
exit $?
