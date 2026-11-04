#!/bin/sh
# adf-agent — lightweight probe executor for Advanced DPI Fuzzer.
#
# Runs on OpenWrt (busybox ash) or any POSIX shell with curl. It never touches
# firewall, routing, UCI or Tachyon configuration: every measurement goes through
# a *temporary* engine bound to 127.0.0.1 (tachyon-core "mixed" inbound or ByeDPI
# SOCKS), started and killed by this script. Probe traffic leaves with the
# routing mark supplied by the controller (Tachyon's bypass mark by default), so
# Tachyon's own TProxy does not capture it.
#
# Commands:
#   adf-agent version
#   adf-agent env                       -> one JSON line describing the host
#   adf-agent resolve <host> [server]   -> one IP per line (A and AAAA)
#   adf-agent caps < tests              -> JSON lines {key,value,ok}; tests are
#                                          "key<TAB>value<TAB>config-json" lines
#   adf-agent run < job                 -> JSON lines, see docs/openwrt-agent.md
#   adf-agent stop                      -> kill engines started by the agent
#   adf-agent tachyon-probe <engine> <args> <url>
#                                       -> delegate one probe to Tachyon's own
#                                          fuzzer (nft changes are Tachyon's own;
#                                          the controller only calls this with an
#                                          explicit --allow-tachyon-probe)
#
#   hold <seconds> <job               -> start the engine from a job and leave it
#                                        running for a client on this host, at most
#                                        <seconds>, until `stop`
#
# Environment overrides: ADF_STATE (/tmp/adf-agent), ADF_CORE (tachyon-core path),
# ADF_BYEDPI (ciadpi path), ADF_MIN_MEM_KB (24576), ADF_CURL (curl).

ADF_AGENT_VERSION="0.1.0"
ADF_STATE="${ADF_STATE:-/tmp/adf-agent}"
ADF_MIN_MEM_KB="${ADF_MIN_MEM_KB:-24576}"
ADF_CURL="${ADF_CURL:-curl}"

log() { printf '%s\n' "adf-agent: $*" >&2; }

json_str() {
	# minimal JSON string escaping for values we emit (ids, paths, short errors)
	printf '"%s"' "$(printf '%s' "$1" | tr -d '\000-\037' | sed 's/\\/\\\\/g; s/"/\\"/g' | cut -c1-300)"
}

find_bin() {
	for c in "$@"; do
		[ -n "$c" ] || continue
		case "$c" in
			/*) [ -x "$c" ] && { echo "$c"; return 0; } ;;
			*) p=$(command -v "$c" 2>/dev/null) && [ -n "$p" ] && { echo "$p"; return 0; } ;;
		esac
	done
	return 1
}

core_bin() {
	# a requested core must not be replaced by the installed one: the run would measure the wrong version
	if [ -n "$ADF_CORE" ]; then
		find_bin "$ADF_CORE"
	else
		find_bin /usr/bin/tachyon-core tachyon-core
	fi
}
byedpi_bin() { find_bin "$ADF_BYEDPI" /opt/byedpi/ciadpi /usr/bin/ciadpi ciadpi; }

mem_avail_kb() {
	awk '/^MemAvailable:/ {print $2; f=1} END {if (!f) print 0}' /proc/meminfo 2>/dev/null || echo 0
}

ensure_state() {
	mkdir -p "$ADF_STATE" 2>/dev/null || { log "cannot create $ADF_STATE"; exit 2; }
	chmod 700 "$ADF_STATE" 2>/dev/null
}

acquire_lock() {
	ensure_state
	if ! mkdir "$ADF_STATE/lock" 2>/dev/null; then
		oldpid=$(cat "$ADF_STATE/lock/pid" 2>/dev/null)
		if [ -n "$oldpid" ] && kill -0 "$oldpid" 2>/dev/null; then
			printf '{"t":"error","error":"busy","pid":%s}\n' "$oldpid"
			exit 3
		fi
		rm -rf "$ADF_STATE/lock"
		mkdir "$ADF_STATE/lock" || exit 3
	fi
	echo $$ > "$ADF_STATE/lock/pid"
}

release_lock() { rm -rf "$ADF_STATE/lock" 2>/dev/null; }

kill_engine() {
	if [ -f "$ADF_STATE/engine.pid" ]; then
		pid=$(cat "$ADF_STATE/engine.pid" 2>/dev/null)
		if [ -n "$pid" ]; then
			kill "$pid" 2>/dev/null
			i=0
			while kill -0 "$pid" 2>/dev/null && [ $i -lt 20 ]; do sleep 0.1 2>/dev/null || sleep 1; i=$((i + 1)); done
			kill -9 "$pid" 2>/dev/null
		fi
		rm -f "$ADF_STATE/engine.pid"
	fi
	if [ -f "$ADF_STATE/hold.pid" ]; then
		kill "$(cat "$ADF_STATE/hold.pid" 2>/dev/null)" 2>/dev/null
		rm -f "$ADF_STATE/hold.pid"
	fi
}

cleanup() {
	kill_engine
	rm -f "$ADF_STATE"/cfg.json "$ADF_STATE"/body.* "$ADF_STATE"/engine.err 2>/dev/null
	release_lock
}

port_listening() {
	# $1 = decimal port. Checks /proc/net/tcp{,6} for a LISTEN (0A) socket.
	hex=$(printf '%04X' "$1")
	cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | awk -v h=":$hex" '$2 ~ h"$" && $4 == "0A" {f=1} END {exit !f}'
}

msleep() {
	ms=$1
	[ "$ms" -gt 0 ] 2>/dev/null || return 0
	s=$(awk -v m="$ms" 'BEGIN {printf "%.3f", m / 1000}')
	sleep "$s" 2>/dev/null || sleep $(( (ms + 999) / 1000 ))
}

# ------------------------------------------------------------------- commands

cmd_env() {
	core=$(core_bin)
	core_ver=""
	[ -n "$core" ] && core_ver=$("$core" version 2>/dev/null | head -n1)
	bd=$(byedpi_bin)
	curl_ver=$($ADF_CURL --version 2>/dev/null | head -n1)
	http3=0
	$ADF_CURL --version 2>/dev/null | grep -qi 'HTTP3' && http3=1
	rel=""
	[ -r /etc/openwrt_release ] && rel=$(. /etc/openwrt_release 2>/dev/null; echo "$DISTRIB_DESCRIPTION")
	tachyon=0
	[ -r /usr/lib/tachyon/diagnostics/fuzzer.uc ] && tachyon=1
	load=$(cut -d' ' -f1 /proc/loadavg 2>/dev/null)
	printf '{"t":"env","agent":%s,"host":%s,"arch":%s,"release":%s,"core":%s,"core_version":%s,"byedpi":%s,"curl":%s,"http3":%s,"tachyon":%s,"mem_avail_kb":%s,"load":%s,"nproc":%s}\n' \
		"$(json_str "$ADF_AGENT_VERSION")" "$(json_str "$(cat /proc/sys/kernel/hostname 2>/dev/null)")" \
		"$(json_str "$(uname -m)")" "$(json_str "$rel")" "$(json_str "$core")" "$(json_str "$core_ver")" \
		"$(json_str "$bd")" "$(json_str "$curl_ver")" "$http3" "$tachyon" "$(mem_avail_kb)" \
		"$(json_str "${load:-0}")" "$(grep -c ^processor /proc/cpuinfo 2>/dev/null || echo 1)"
}

cmd_resolve() {
	host=$1
	server=$2
	[ -n "$host" ] || { log "resolve: host required"; exit 2; }
	# busybox and bind nslookup both print "Address: <ip>" (bind adds "#53" for the server)
	nslookup "$host" $server 2>/dev/null | awk '
		/^Name:/ {seen=1; next}
		seen && /^Address/ {
			for (i = 2; i <= NF; i++) { a=$i; sub(/#.*/, "", a); if (a ~ /^[0-9a-fA-F.:]+$/ && a != "") print a }
		}' | sort -u
}

cmd_caps() {
	core=$(core_bin) || { printf '{"t":"error","error":"tachyon-core not found"}\n'; exit 4; }
	ensure_state
	tab=$(printf '\t')
	while IFS="$tab" read -r key value cfg; do
		[ -n "$key" ] || continue
		printf '%s\n' "$cfg" > "$ADF_STATE/caps.json"
		if "$core" check -c "$ADF_STATE/caps.json" >/dev/null 2>"$ADF_STATE/caps.err"; then ok=true; else ok=false; fi
		err=$(head -n1 "$ADF_STATE/caps.err" 2>/dev/null)
		printf '{"t":"caps","key":%s,"value":%s,"ok":%s,"error":%s}\n' "$(json_str "$key")" "$(json_str "$value")" "$ok" "$(json_str "$err")"
	done
	rm -f "$ADF_STATE/caps.json" "$ADF_STATE/caps.err"
}

start_engine() {
	# $1 kind (tachyon|byedpi), $2 port
	kind=$1
	port=$2
	kill_engine
	rm -f "$ADF_STATE/engine.err"
	case "$kind" in
		tachyon)
			core=$(core_bin) || { printf '{"t":"engine","ok":false,"error":"tachyon-core not found"}\n'; return 1; }
			"$core" check -c "$ADF_STATE/cfg.json" >/dev/null 2>"$ADF_STATE/engine.err" || {
				printf '{"t":"engine","ok":false,"error":%s}\n' "$(json_str "config rejected: $(head -n1 "$ADF_STATE/engine.err")")"
				return 1
			}
			( exec "$core" run -c "$ADF_STATE/cfg.json" >/dev/null 2>>"$ADF_STATE/engine.err" ) &
			echo $! > "$ADF_STATE/engine.pid"
			;;
		byedpi)
			bd=$(byedpi_bin) || { printf '{"t":"engine","ok":false,"error":"ciadpi not found"}\n'; return 1; }
			# shellcheck disable=SC2086
			( exec "$bd" -i 127.0.0.1 -p "$port" $BYEDPI_ARGS >/dev/null 2>>"$ADF_STATE/engine.err" ) &
			echo $! > "$ADF_STATE/engine.pid"
			;;
		*)
			printf '{"t":"engine","ok":false,"error":%s}\n' "$(json_str "unknown engine kind $kind")"
			return 1
			;;
	esac
	pid=$(cat "$ADF_STATE/engine.pid")
	i=0
	while [ $i -lt $((ENGINE_START_S * 10)) ]; do
		if ! kill -0 "$pid" 2>/dev/null; then
			printf '{"t":"engine","ok":false,"error":%s}\n' "$(json_str "engine exited: $(head -n1 "$ADF_STATE/engine.err" 2>/dev/null)")"
			rm -f "$ADF_STATE/engine.pid"
			return 1
		fi
		port_listening "$port" && { printf '{"t":"engine","ok":true,"pid":%s}\n' "$pid"; return 0; }
		msleep 100
		i=$((i + 1))
	done
	printf '{"t":"engine","ok":false,"error":"engine did not open its port within %ss"}\n' "$ENGINE_START_S"
	kill_engine
	return 1
}

probe_one() {
	# $1 id $2 family $3 url $4 ip $5 min_bytes $6 range $7 kind $8 regex(base64-free, '-' none) $9 rep
	id=$1; fam=$2; url=$3; ip=$4; minb=$5; range=$6; kind=$7; rx=$8; rep=$9
	set --
	scheme=socks5h
	if [ "$ip" != "-" ]; then
		host=$(printf '%s' "$url" | sed -n 's#^[a-z]*://\([^/:]*\).*#\1#p')
		port=$(printf '%s' "$url" | sed -n 's#^[a-z]*://[^/:]*:\([0-9][0-9]*\).*#\1#p')
		if [ -z "$port" ]; then
			port=443
			case "$url" in http://*) port=80 ;; esac
		fi
		case "$ip" in *:*) rip="[$ip]" ;; *) rip=$ip ;; esac
		set -- --resolve "$host:$port:$rip"
		scheme=socks5
	fi
	case "$fam" in ipv4) set -- "$@" -4 ;; ipv6) set -- "$@" -6 ;; esac
	[ "$range" != "-" ] && set -- "$@" -r "$range"
	[ "$kind" = "quic" ] && set -- "$@" --http3-only
	[ -n "$CACERT" ] && set -- "$@" --cacert "$CACERT"
	if [ "$ENGINE_KIND" != "none" ]; then set -- "$@" -x "$scheme://127.0.0.1:$PORT"; fi
	body="$ADF_STATE/body.$$"
	out=$($ADF_CURL -sS -o "$body" --max-filesize 4194304 --connect-timeout "$CONNECT_TIMEOUT" --max-time "$TIMEOUT" \
		-A "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0" \
		-w '%{http_code} %{time_connect} %{time_appconnect} %{time_starttransfer} %{time_total} %{size_download} %{speed_download} %{remote_ip}' \
		"$@" "$url" 2>"$ADF_STATE/curl.err")
	rc=$?
	PROBE_RC=$rc
	content=null
	if [ "$rx" != "-" ] && [ -s "$body" ]; then
		if grep -Eq "$rx" "$body" 2>/dev/null; then content=1; else content=0; fi
	fi
	rm -f "$body"
	set -- $out
	code=${1:-0}; tc=${2:-0}; ta=${3:-0}; tf=${4:-0}; tt=${5:-0}; size=${6:-0}; speed=${7:-0}; rip=${8:-}
	err=$(head -n1 "$ADF_STATE/curl.err" 2>/dev/null)
	printf '{"t":"probe","target":%s,"rep":%s,"family":%s,"ip":%s,"code":%s,"exit":%s,"tc":%s,"ta":%s,"tf":%s,"tt":%s,"size":%s,"speed":%s,"rip":%s,"content":%s,"min_bytes":%s,"error":%s}\n' \
		"$(json_str "$id")" "$rep" "$(json_str "$fam")" "$(json_str "$ip")" "$((code + 0))" "$rc" "$tc" "$ta" "$tf" "$tt" \
		"$size" "$speed" "$(json_str "$rip")" "$content" "$minb" "$(json_str "$err")"
}

read_job() {
	ENGINE_KIND=none; PORT=11290; REPS=1; INTERVAL_MS=250; TIMEOUT=8; CONNECT_TIMEOUT=4; BYEDPI_ARGS=""; CACERT=""
	STOP_ON_FAIL=0
	ENGINE_START_S=10
	targets="$ADF_STATE/targets"
	: > "$targets"
	section=""
	read -r magic ver || { log "empty job"; exit 2; }
	[ "$magic" = "ADF-JOB" ] && [ "$ver" = 1 ] || { log "bad job header (expected ADF-JOB 1)"; exit 2; }
	while IFS= read -r line; do
		case "$section" in
			config)
				if [ "$line" = "config-end" ]; then section=""; else printf '%s\n' "$line" >> "$ADF_STATE/cfg.json"; fi
				continue ;;
		esac
		set -- $line
		case "$1" in
			engine) ENGINE_KIND=$2 ;;
			port) PORT=$2 ;;
			reps) REPS=$2 ;;
			interval_ms) INTERVAL_MS=$2 ;;
			timeout) TIMEOUT=$2 ;;
			connect_timeout) CONNECT_TIMEOUT=$2 ;;
			cacert) CACERT=$2 ;;
			stop_on_fail) STOP_ON_FAIL=$2 ;;
			engine_start_s) ENGINE_START_S=$2 ;;
			byedpi_args) shift; BYEDPI_ARGS="$*" ;;
			config-begin) : > "$ADF_STATE/cfg.json"; section=config ;;
			target) shift; printf '%s\n' "$*" >> "$targets" ;;
			end) break ;;
			"") ;;
			*) log "ignoring job line: $1" ;;
		esac
	done
	avail=$(mem_avail_kb)
	if [ "$avail" -gt 0 ] && [ "$avail" -lt "$ADF_MIN_MEM_KB" ]; then
		printf '{"t":"error","error":"low memory","mem_avail_kb":%s}\n' "$avail"
		exit 5
	fi
}

cmd_run() {
	acquire_lock
	trap cleanup EXIT
	trap 'cleanup; exit 130' INT TERM
	read_job
	if [ "$ENGINE_KIND" != "none" ]; then
		start_engine "$ENGINE_KIND" "$PORT" || { printf '{"t":"done","ok":false}\n'; exit 0; }
	fi
	rep=1
	while [ "$rep" -le "$REPS" ]; do
		while read -r id fam url ip minb range kind rx; do
			[ -n "$id" ] || continue
			if [ "$ENGINE_KIND" != "none" ] && ! kill -0 "$(cat "$ADF_STATE/engine.pid" 2>/dev/null)" 2>/dev/null; then
				printf '{"t":"engine","ok":false,"error":"engine crashed during probes"}\n'
				printf '{"t":"done","ok":false}\n'
				exit 0
			fi
			probe_one "$id" "$fam" "$url" "$ip" "$minb" "$range" "$kind" "$rx" "$rep"
			msleep "$INTERVAL_MS"
			if [ "$STOP_ON_FAIL" = 1 ] && [ "$PROBE_RC" != 0 ]; then
				printf '{"t":"stopped_on_fail","target":%s}\n' "$(json_str "$id")"
				break 2
			fi
		done < "$targets"
		rep=$((rep + 1))
	done
	printf '{"t":"done","ok":true,"mem_avail_kb":%s}\n' "$(mem_avail_kb)"
}

cmd_hold() {
	# the controller talks to the engine itself, then calls `stop`; if it disappears, the engine stops here
	hold_s=$1
	acquire_lock
	trap release_lock EXIT
	read_job
	start_engine "$ENGINE_KIND" "$PORT" || { printf '{"t":"done","ok":false}\n'; exit 0; }
	pid=$(cat "$ADF_STATE/engine.pid")
	(
		sleep "$hold_s"
		rm -f "$ADF_STATE/hold.pid"
		[ "$(cat "$ADF_STATE/engine.pid" 2>/dev/null)" = "$pid" ] && kill_engine
	) </dev/null >/dev/null 2>&1 &
	echo $! > "$ADF_STATE/hold.pid"
	printf '{"t":"done","ok":true}\n'
}

cmd_tachyon_probe() {
	[ -r /usr/lib/tachyon/diagnostics/fuzzer.uc ] || { printf '{"t":"error","error":"Tachyon fuzzer not installed"}\n'; exit 4; }
	acquire_lock
	trap release_lock EXIT
	ucode -L /usr/lib/tachyon -- /usr/lib/tachyon/diagnostics/fuzzer.uc probe "$1" "$2" custom "$3" "adf_$$"
}

case "$1" in
	version) echo "$ADF_AGENT_VERSION" ;;
	env) cmd_env ;;
	resolve) shift; cmd_resolve "$@" ;;
	caps) cmd_caps ;;
	run) cmd_run ;;
	hold) shift; cmd_hold "$@" ;;
	stop) ensure_state; kill_engine; release_lock; echo '{"t":"stopped"}' ;;
	tachyon-probe) shift; cmd_tachyon_probe "$@" ;;
	*) echo "usage: adf-agent {version|env|resolve|caps|run|hold|stop|tachyon-probe}" >&2; exit 1 ;;
esac
