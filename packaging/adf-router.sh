#!/bin/sh
# adf-router — runs Advanced DPI Fuzzer on the router itself, without a PC.
#
#   adf-router check [service[,service]] [--minutes N] [-- adf-run-args]
#   adf-router run [--categories a,b] [--minutes N] [--report FILE] [--foreground] [-- adf-run-args]
#   adf-router status | log [-f] | stop | report | best | uninstall [--purge] | help
#
# The search runs in the background and survives the SSH session. It only measures: Tachyon's
# configuration changes solely through `adf apply`, which asks for confirmation.
#
# Environment overrides (used by tests): ADF_PREFIX (/opt/adf), ADF_BIN_DIR (/usr/bin),
# ADF_CONF_DIR (/etc/adf), ADF_TTY (/dev/tty), ADF_MEMINFO (/proc/meminfo).

PREFIX="${ADF_PREFIX:-/opt/adf}"
BIN_DIR="${ADF_BIN_DIR:-/usr/bin}"
CONF_DIR="${ADF_CONF_DIR:-/etc/adf}"
TTY="${ADF_TTY:-/dev/tty}"
STATE_DIR="${HOME:-/root}/.adf"
LOG="$STATE_DIR/run.log"
PID_FILE="$STATE_DIR/run.pid"
REPORTS="$STATE_DIR/reports"
DEFAULT_CATEGORIES="youtube,discord"
DEFAULT_MINUTES=60
PY_LIGHT="python3-light python3-sqlite3 python3-decimal python3-urllib"
NEED_FLASH_MB=3     # ADF, compiled bytecode, results database
NEED_PYTHON_MB=20   # 14.4 MB of packages on OpenWrt 25.12, plus a margin
LOW_MEMORY_MB=96    # search: controller 28 MB, temporary engine up to 46 MB, curl, agent's 24 MB reserve
PC_HINT="Alternative: run ADF on a PC over SSH, the router then needs neither Python nor this space (see README)."
PY_CHECK="import sys; assert sys.version_info >= (3, 11); import argparse, dataclasses, datetime, hashlib, ipaddress, json, pathlib, random, shlex, sqlite3, statistics, subprocess, tomllib"

die() { printf 'adf-router: %s\n' "$*" >&2; exit 1; }

usage() {
	cat <<EOF
Advanced DPI Fuzzer on the router.

  adf-router check [service] pick a service and depth, run the search, show the result
      --minutes N            skip the depth question
      -- ...                 extra arguments for \`adf run\`
  adf-router run [options]   start a search in the background and return
      --categories a,b       targets (default: $DEFAULT_CATEGORIES)
      --minutes N            time budget (default: $DEFAULT_MINUTES)
      --report FILE          report path (default: $REPORTS/run-<date>.md)
      --foreground           stay attached instead of running in the background
      -- ...                 extra arguments for \`adf run\`
  adf-router status          is a search running, last log lines
  adf-router log [-f]        show (or follow) the search log
  adf-router stop            stop the search; collected data is kept
  adf-router report          print the latest report
  adf-router best            best strategies measured so far
  adf-router uninstall [--purge]  remove ADF (--purge also deletes results and config)

Everything else is available through \`adf\`: adf caps, adf import, adf compare, adf apply.
Tachyon's configuration is changed only by \`adf apply\`, after a typed confirmation.
EOF
}

python_ok() { python3 -c "$PY_CHECK" >/dev/null 2>&1; }

free_flash_mb() {
	d=$PREFIX
	while [ ! -d "$d" ]; do d=$(dirname "$d"); done
	df -Pk "$d" 2>/dev/null | awk 'NR == 2 { print int($4 / 1024) }'
}

available_memory_mb() {
	awk '/^MemAvailable:/ { print int($2 / 1024) }' "${ADF_MEMINFO:-/proc/meminfo}" 2>/dev/null
}

warn_low_memory() {
	avail=$(available_memory_mb)
	if [ -n "$avail" ] && [ "$avail" -lt "$LOW_MEMORY_MB" ]; then
		echo "warning: only $avail MB of memory available, a search needs about $LOW_MEMORY_MB MB."
		echo "$PC_HINT"
	fi
}

preflight() {
	need=$NEED_FLASH_MB
	[ "$1" = 1 ] && need=$((need + NEED_PYTHON_MB))
	free=$(free_flash_mb)
	if [ -n "$free" ] && [ "$free" -lt "$need" ]; then
		[ "$2" = 1 ] || die "not enough flash: $free MB free, $need MB needed (--force to try anyway). $PC_HINT"
		echo "warning: only $free MB of flash free, $need MB needed; continuing because of --force."
	fi
	warn_low_memory
}

install_python() {
	if command -v apk >/dev/null 2>&1; then
		apk update >/dev/null 2>&1 || true
		# shellcheck disable=SC2086  # the list is meant to split into package names
		apk add $PY_LIGHT >/dev/null 2>&1 || true
		python_ok || apk add python3 || return 1
	elif command -v opkg >/dev/null 2>&1; then
		opkg update >/dev/null 2>&1 || true
		# shellcheck disable=SC2086  # the list is meant to split into package names
		opkg install $PY_LIGHT >/dev/null 2>&1 || true
		python_ok || opkg install python3 || return 1
	else
		return 1
	fi
	python_ok
}

is_running() {
	[ -f "$PID_FILE" ] || return 1
	pid=$(cat "$PID_FILE" 2>/dev/null)
	[ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

write_wrapper() {
	cat > "$BIN_DIR/adf" <<EOF
#!/bin/sh
case "\${1:-}" in
	-c|--config) ;;
	*) set -- -c "$CONF_DIR/config.toml" "\$@" ;;
esac
PYTHONPATH="$PREFIX/lib" ADF_AGENT_PATH="$PREFIX/agent/adf-agent.sh" exec python3 -m adf "\$@"
EOF
	chmod 755 "$BIN_DIR/adf"
}

cmd_install() {
	src=$1
	shift
	deps=1
	force=0
	while [ $# -gt 0 ]; do
		case "$1" in
			--no-deps) deps=0 ;;
			--force) force=1 ;;
			*) die "unknown option $1" ;;
		esac
		shift
	done
	if [ -z "${ADF_PREFIX:-}" ] && [ "$(id -u)" != 0 ]; then
		die "run as root"
	fi
	is_running && die "a search is running: stop it first (adf-router stop)"
	command -v curl >/dev/null 2>&1 || die "curl is required"
	if python_ok; then
		preflight 0 "$force"
	else
		[ "$deps" = 1 ] || die "Python >= 3.11 with sqlite3 is required (--no-deps was given)"
		preflight 1 "$force"
		echo "Installing Python (once)..."
		install_python || die "could not install Python >= 3.11: check the internet access, package feeds and firmware version. $PC_HINT"
	fi
	new="$PREFIX.new"
	rm -rf "$new"
	mkdir -p "$new" "$BIN_DIR" "$CONF_DIR" "$REPORTS" || die "cannot create directories"
	cp -R "$src/lib" "$src/agent" "$src/VERSION" "$new/" || die "cannot copy files to $new"
	PYTHONPATH="$new/lib" python3 -c "import adf.cli" || { rm -rf "$new"; die "installed Python cannot run ADF"; }
	rm -rf "$PREFIX.old"
	if [ -d "$PREFIX" ]; then mv "$PREFIX" "$PREFIX.old"; fi
	mv "$new" "$PREFIX"
	rm -rf "$PREFIX.old"
	cp "$src/bin/adf-router" "$BIN_DIR/adf-router"
	chmod 755 "$BIN_DIR/adf-router"
	write_wrapper
	if [ ! -f "$CONF_DIR/config.toml" ]; then
		cat > "$CONF_DIR/config.toml" <<'EOF'
# Advanced DPI Fuzzer on the router (keys: examples/config.toml in the repository)
[router]
local = true

[search]
network_id = "home"
EOF
	fi
	"$BIN_DIR/adf" validate "mode=split split_pos=1" >/dev/null || die "self-check failed"
	command -v tachyon-core >/dev/null 2>&1 || echo "warning: tachyon-core not found: searches will not start"
	echo "Advanced DPI Fuzzer $(cat "$PREFIX/VERSION") installed in $PREFIX."
	echo "Start a check:   adf-router check"
	echo "All commands:    adf-router help"
}

cmd_worker() {
	report=$1
	shift
	"$BIN_DIR/adf" run --yes --report "$report" "$@"
	echo "search finished, exit code $?; report: $report"
}

cmd_run() {
	categories=$DEFAULT_CATEGORIES
	minutes=$DEFAULT_MINUTES
	report=""
	foreground=0
	while [ $# -gt 0 ]; do
		case "$1" in
			--categories) [ $# -ge 2 ] || die "--categories needs a value"; categories=$2; shift 2 ;;
			--minutes) [ $# -ge 2 ] || die "--minutes needs a value"; minutes=$2; shift 2 ;;
			--report) [ $# -ge 2 ] || die "--report needs a value"; report=$2; shift 2 ;;
			--foreground) foreground=1; shift ;;
			--) shift; break ;;
			*) die "unknown option $1 (see: adf-router help)" ;;
		esac
	done
	is_running && die "a search is already running (adf-router status)"
	mkdir -p "$REPORTS" || die "cannot create $REPORTS"
	[ -n "$report" ] || report="$REPORTS/run-$(date +%Y%m%d-%H%M%S).md"
	set -- --categories "$categories" --max-minutes "$minutes" "$@"
	if [ "$foreground" = 1 ]; then
		exec "$BIN_DIR/adf-router" __worker "$report" "$@"
	fi
	: > "$LOG"
	if command -v setsid >/dev/null 2>&1; then
		setsid "$BIN_DIR/adf-router" __worker "$report" "$@" </dev/null >>"$LOG" 2>&1 &
	else
		( trap '' HUP; exec "$BIN_DIR/adf-router" __worker "$report" "$@" ) </dev/null >>"$LOG" 2>&1 &
	fi
	echo $! > "$PID_FILE"
	echo "Search started in the background: $categories, up to $minutes min."
	echo "Progress: adf-router status   Stop: adf-router stop"
	echo "Report:   $report"
}

ask() {
	printf '%s' "$1"
	IFS= read -r answer <&3 || die "no answer from the terminal"
}

choose_service() {
	services=$("$BIN_DIR/adf" targets | awk '$2 != "control" && !seen[$2]++ { print $2 }')
	[ -n "$services" ] || die "the target list is empty"
	echo "Which service to check?"
	i=0
	for s in $services; do
		i=$((i + 1))
		printf '  %d) %s\n' "$i" "$s"
	done
	echo "  a) all of them"
	ask "Number, or several like 1,3: "
	case "$answer" in
		a|A) service=$(echo "$services" | tr '\n' ',' | sed 's/,$//'); return ;;
	esac
	service=""
	for n in $(echo "$answer" | tr ',' ' '); do
		case "$n" in
			*[!0-9]*) die "not a number: $n" ;;
		esac
		s=$(echo "$services" | sed -n "${n}p")
		[ -n "$s" ] || die "no service number $n"
		service="${service:+$service,}$s"
	done
	[ -n "$service" ] || die "no service chosen"
}

choose_minutes() {
	echo "How long?"
	echo "  1) quick, 5 min: a first working strategy"
	echo "  2) normal, 20 min"
	echo "  3) full, 60 min: the most reliable result"
	ask "Number [1]: "
	case "$answer" in
		""|1) minutes=5 ;;
		2) minutes=20 ;;
		3) minutes=60 ;;
		*) die "choose 1, 2 or 3" ;;
	esac
}

follow() {
	tail -n +1 -f "$LOG" &
	tail_pid=$!
	trap 'kill "$tail_pid" 2>/dev/null; echo; echo "The search continues in the background: adf-router status"; exit 0' INT
	started=$(date +%s)
	next=60
	while is_running; do
		sleep 2
		elapsed=$(($(date +%s) - started))
		if [ "$elapsed" -ge "$next" ]; then
			printf 'still working: %d of up to %s min. Ctrl+C leaves it running in the background.\n' \
				"$((elapsed / 60))" "$1"
			next=$((next + 60))
		fi
	done
	kill "$tail_pid" 2>/dev/null
	trap - INT
}

cmd_check() {
	service=""
	minutes=""
	while [ $# -gt 0 ]; do
		case "$1" in
			--minutes) [ $# -ge 2 ] || die "--minutes needs a value"; minutes=$2; shift 2 ;;
			--) shift; break ;;
			-*) die "unknown option $1 (see: adf-router help)" ;;
			*) service=$1; shift ;;
		esac
	done
	is_running && die "a search is already running (adf-router status)"
	if [ -z "$service" ] || [ -z "$minutes" ]; then
		( : <"$TTY" ) 2>/dev/null || die "no terminal: pass both, e.g. adf-router check youtube --minutes 5"
		exec 3<"$TTY"
		[ -n "$service" ] || choose_service
		[ -n "$minutes" ] || choose_minutes
		exec 3<&-
	fi
	warn_low_memory
	# Current Tachyon strategies become candidates, so the search also measures what is in use.
	"$BIN_DIR/adf" import >/dev/null 2>&1
	report="$REPORTS/run-$(date +%Y%m%d-%H%M%S).md"
	"$BIN_DIR/adf-router" run --categories "$service" --minutes "$minutes" --report "$report" -- "$@" || exit 1
	echo
	follow "$minutes"
	echo
	[ -f "$report" ] || die "the search ended without a report, see: adf-router log"
	cat "$report"
	echo
	echo "Strategies with ids: adf-router best"
	echo "Apply one:           adf apply --section <section> <id> --dry-run"
	echo "Nothing was changed in Tachyon."
}

cmd_status() {
	if is_running; then
		echo "running (pid $(cat "$PID_FILE"))"
	else
		echo "not running"
	fi
	[ -f "$LOG" ] && tail -n 5 "$LOG"
	return 0
}

cmd_log() {
	[ -f "$LOG" ] || die "no search has been started yet"
	if [ "${1:-}" = "-f" ]; then
		exec tail -f "$LOG"
	fi
	tail -n 40 "$LOG"
}

cmd_stop() {
	if ! is_running; then
		echo "not running"
		return 0
	fi
	"$BIN_DIR/adf" stop --local >/dev/null 2>&1
	i=0
	while is_running && [ $i -lt 45 ]; do
		sleep 1
		i=$((i + 1))
	done
	if is_running; then
		pid=$(cat "$PID_FILE")
		kill -TERM "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null
	fi
	echo "stopped; collected data is kept"
}

cmd_report() {
	latest=$(ls -t "$REPORTS"/*.md 2>/dev/null | head -n 1)
	[ -n "$latest" ] || die "no reports yet"
	echo "# $latest"
	cat "$latest"
}

cmd_uninstall() {
	is_running && die "a search is running: stop it first (adf-router stop)"
	rm -rf "$PREFIX" "$PREFIX.new" "$PREFIX.old" "$BIN_DIR/adf"
	if [ "${1:-}" = "--purge" ]; then
		rm -rf "$CONF_DIR" "$STATE_DIR"
		echo "ADF, its config and results removed."
	else
		echo "ADF removed; config ($CONF_DIR) and results ($STATE_DIR) kept."
	fi
	echo "Python stays installed: remove it with your package manager if nothing else needs it."
	rm -f "$BIN_DIR/adf-router"
}

case "${1:-help}" in
	__install) shift; cmd_install "$@" ;;
	__worker) shift; cmd_worker "$@" ;;
	check) shift; cmd_check "$@" ;;
	run) shift; cmd_run "$@" ;;
	status) cmd_status ;;
	log) shift; cmd_log "$@" ;;
	stop) cmd_stop ;;
	report) cmd_report ;;
	best) exec "$BIN_DIR/adf" best ;;
	uninstall) shift; cmd_uninstall "$@" ;;
	help|-h|--help) usage ;;
	*) printf 'adf-router: unknown command %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
esac
