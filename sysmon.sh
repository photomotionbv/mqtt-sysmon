#!/usr/bin/env bash

set -euo pipefail

SYSMON_MQTT_VERSION='2.0.0'
echo "mqtt-sysmon $SYSMON_MQTT_VERSION (Photo-Motion)"

if [ "$*" == "--version" ]; then
  exit 0
fi

# Defaults for optional settings (from global environment)

: "${SYSMON_INTERVAL:=30}"
: "${SYSMON_APT:=true}"
: "${SYSMON_APT_CHECK:=}"
: "${SYSMON_RTT_COUNT:=4}"
: "${SYSMON_DAEMON_LOG:="$HOME/sysmon-mqtt.log"}"

# Simple daemon

if [ "$1" == "--daemon" ]; then

  touch "$SYSMON_DAEMON_LOG" || exit 1

  trap 'trap - EXIT; [ -n "$(jobs -pr)" ] && kill $(jobs -pr); exit 0' \
    INT HUP TERM EXIT

  shift

  echo "Spawning sysmon-mqtt; redirecting all output to $SYSMON_DAEMON_LOG..."
  echo "--- $(date -R) ---" >> "$SYSMON_DAEMON_LOG"

  while true; do

    nohup "$0" "$@" >> "$SYSMON_DAEMON_LOG" 2>&1 &

    # Capture the child-process exit-code, while at the same time masking it
    # from the shell (to prevent "set -e" from exiting us)
    wait $! && rc=$? || rc=$?

    printf 'Child exited with code %d; respawning in %d seconds...\n' \
      "$rc" "$SYSMON_INTERVAL" >> "$SYSMON_DAEMON_LOG"

    sleep $((10#$SYSMON_INTERVAL)) &
    wait $!

    echo "--- $(date -R) ---" >> "$SYSMON_DAEMON_LOG"

  done

fi

# Compute number of ticks per hour; additionally, forces $SYSMON_INTERVAL to
# base10 — exits in case of an invalid value for the interval

hourly_ticks=$((3600 / 10#$SYSMON_INTERVAL))

# Positional parameters

mqtt_host="${1:?"Missing MQTT-broker hostname!"}"
device_name="${2:?"Missing device name!"}"

# Optional
topic="${3:="sysmon"}"
read -r -a eth_adapters <<< "${4:-}"
read -r -a rtt_hosts <<< "${5:-}"

# Expand wildcard patterns in eth_adapters (e.g., wlx* -> actual device names)
expanded_adapters=()
shopt -s nullglob
for adapter in "${eth_adapters[@]}"; do
  if [[ "$adapter" == *"*"* ]]; then
    for match in /sys/class/net/${adapter}; do
      expanded_adapters+=("$(basename "$match")")
    done
  else
    expanded_adapters+=("$adapter")
  fi
done
shopt -u nullglob
eth_adapters=("${expanded_adapters[@]}")

# When round-trip times are to be reported, ensure the reporting interval is
# longer than the maximum time required to complete all of the ping-commands.
# This to prevent people from shooting themselves in the foot by setting the
# interval too low and spawning an ever increasing number of ping-commands.

if [ ${#rtt_hosts[@]} -gt 0 ]; then
  minimum_interval=$(((10#$SYSMON_RTT_COUNT + 1) * ${#rtt_hosts[@]} + (\
    10#$SYSMON_INTERVAL * 2 / 10)))
  if [ $((10#$SYSMON_INTERVAL)) -lt $minimum_interval ]; then
    echo " \-> Increased SYSMON_INTERVAL to $minimum_interval"
    SYSMON_INTERVAL=$minimum_interval
  fi
fi

# Exit-trap handler

goodbye() {

  rc="$?"

  # Reset EXIT-trap to prevent getting stuck in "goodbye" (due to "set -e")
  trap - EXIT

  # Terminate all child-processes
  if [ -n "$(jobs -pr)" ]; then
    read -ra pids < <(jobs -pr)
    kill "${pids[@]}"
  fi

  # Clean-up temporary files and fds/pipes
  if [ -v apt_check ] && [ -f "$apt_check" ]; then
    rm -f "$apt_check"
  fi
  if { : >&3; } 2> /dev/null; then
    exec 3>&-
  fi

  # Sign-off from MQTT
  mosquitto_pub -r -q 1 -h "$mqtt_host" -t "$topic/connected" -m 0 ||
    true

  exit "$rc"
}

# Clean parameters to be used in MQTT-topics and JSON-keys — reduce them to
# lowercase alphanumeric and underscores; exit if nothing remains

mqtt_json_clean() {

  param="${1:?"Missing parameter to clean!"}"

  # It appears Home Assistant doesn't like JSON-keys made up of only numbers and
  # underscores (e.g. the IP-address "8.8.8.8" translated into "8_8_8_8"); I'm
  # guessing the same applies to purely numeric keys...
  # So, prepend "IP " or "N " respectively to the unprocessed input to get more
  # agreeable output (assuming anything which remotely resembles an IP-address
  # is actually one).

  if [[ "$param" =~ ^[0-9.]+$ ]]; then
    param="IP $param"
  elif [[ "$param" =~ ^[0-9]+$ ]]; then
    param="N $param"
  fi

  # The more obvious tr-approach isn't guaranteed to work on BusyBox as its
  # built-in tr might not support case-conversion. As gawk is required anyway,
  # just use that instead on all platforms...

  param=$(echo "${param//[^A-Za-z0-9_ .-/]/}" |
    tr -s ' .' - | gawk '{print tolower($0)}')

  if [ -z "$param" ]; then
    echo "Invalid parameter '$1' supplied!"
    exit 1
  fi

  echo "$param"
}

# Attempt to retrieve the most sensible device-model description

device_model() {

  local payload_model
  payload_model=""

  # Raspberry Pi,et al.
  if [ -f /sys/firmware/devicetree/base/model ]; then
    payload_model=$(
      tr -d '\0' < /sys/firmware/devicetree/base/model || true
    )
  fi

  # Generic SBCs & embedded systems
  if [ -z "$payload_model" ]; then
    payload_model=$(
      grep -i -m 1 hardware /proc/cpuinfo | cut -d ':' -f2 || true
    )
    payload_model="${payload_model/ /}"
  fi

  # PCs (and fallback)
  if [ -z "$payload_model" ]; then
    payload_model=$(
      grep -i -m 1 'model name' /proc/cpuinfo | cut -d ':' -f2 || true
    )
    payload_model="${payload_model/ /}"
  fi

  echo "$payload_model"
}

topic=$(mqtt_json_clean "$topic")

# Test the broker (assumes Mosquitto) — exits on failure
mosquitto_sub -C 1 -h "$mqtt_host" -t \$SYS/broker/version

mosquitto_pub -r -q 1 -h "$mqtt_host" \
  -t "$topic/connected" -m '-1' || true
mosquitto_pub -r -q 1 -h "$mqtt_host" \
  -t "$topic/version" -m "$SYSMON_MQTT_VERSION-pm" || true
mosquitto_pub -r -q 1 -h "$mqtt_host" \
  -t "$topic/device-model" -m "$(device_model)" || true

# Helper functions ("private")

_join() {
  local IFS="$1"
  shift
  echo "$*"
}

_readfd() {
  local IFS=$'\n'
  local lines
  if read -r -u "$1" -t 0 || false; then
    read -r -u "$1" -d '' -a lines
    echo "${lines[@]}"
  fi
}

cpu_cores=$(nproc --all)
rx_prev=()
tx_prev=()
first_loop=true
hourly=true
ticks=0

# APT-check output file (defaults to temporary file)
if [ "$SYSMON_APT" = true ]; then
  if [ -n "$SYSMON_APT_CHECK" ]; then
    touch "$SYSMON_APT_CHECK" && apt_check="$SYSMON_APT_CHECK"
  else
    apt_check=$(mktemp -t sysmon.apt-check.XXXXXXXX)
  fi
fi

# Round-trip times output ("anonymous" pipe; fd 3)
if [ ${#rtt_hosts[@]} -gt 0 ]; then
  rtt_result=$(mktemp -u -t sysmon.rtt.XXXXXXXX)
  mkfifo "$rtt_result" && exec 3<> "$rtt_result"
  rm -f "$rtt_result"
  unset -v rtt_result
fi

payload_rtt=""

# ZFS ARC — minimum size
if [ -f /proc/spl/kstat/zfs/arcstats ]; then
  zfs_arc_min=$(gawk '/^c_min/ {printf "%.0f", $3/1024 }' < \
    /proc/spl/kstat/zfs/arcstats)
fi

while true; do

  # Uptime
  uptime=$(cut -d ' ' -f1 < /proc/uptime)

  # CPU temperature
  if [ -r /sys/class/thermal/thermal_zone0/temp ]; then
    cpu_temp=$(gawk '{printf "%3.2f", $0/1000 }' < \
      /sys/class/thermal/thermal_zone0/temp)
  fi

  # Status (systemd)
  if [ -d /run/systemd/system ]; then
    status=$(systemctl is-system-running || :)
  fi

  # Load (1-minute load / # of cores)
  cpu_load=$(uptime |
    gawk "match(\$0, /load average: ([0-9\.]*),/, \
      result){printf \"%3.2f\", result[1]*100/$cpu_cores}")

  # Memory usage (1 - total / available)
  mem_total=$(free | gawk 'NR==2{print $2}')
  mem_avail=$(free | gawk 'NR==2{print $7}')

  # Disk space available in GiB
  disk_avail=$(
    gawk '{printf "%d", $1/1024/1024}' <<< \
      "$(df -k --output=avail / | tail -n 1)"
  )

  # Account for ZFS ARC — this is "buff/cache", but counted as "used" by the
  # kernel in Linux. Approach taken from btop: If current ARC size is greater
  # than its minimum size (lower than which it'll never go), assume the surplus
  # to be available memory.
  if [ -v zfs_arc_min ] && [ -n "$zfs_arc_min" ]; then
    zfs_arc_size=$(gawk '/^size/ {printf "%.0f", $3/1024}' < \
      /proc/spl/kstat/zfs/arcstats)
    if [ "$zfs_arc_size" -gt "$zfs_arc_min" ]; then
      mem_avail=$((mem_avail + zfs_arc_size - zfs_arc_min))
    fi
  fi

  mem_used=$(gawk \
    '{printf "%3.2f", (1-($1/$2))*100}' <<< "$mem_avail $mem_total")

  # Bandwidth (in kbps; measured over the "sysmon interval")

  payload_bw=()

  for i in "${!eth_adapters[@]}"; do

    eth_adapter="${eth_adapters[i]}"

    # Attempt to strip $adapter down to a single path-component; exits if the
    # adapter doesn't exist
    rx=$(< "/sys/class/net/${eth_adapter%%/*}/statistics/rx_bytes")
    tx=$(< "/sys/class/net/${eth_adapter%%/*}/statistics/tx_bytes")

    # Only run when "prev" is initialised
    if [ "${#rx_prev[@]}" -eq "${#eth_adapters[@]}" ]; then

      payload_rx=$(
        gawk '{printf "%3.2f", ($1-$2)/$3*8/1000}' \
          <<< "$rx ${rx_prev[i]} $((10#$SYSMON_INTERVAL))"
      )
      payload_tx=$(
        gawk '{printf "%3.2f", ($1-$2)/$3*8/1000}' \
          <<< "$tx ${tx_prev[i]} $((10#$SYSMON_INTERVAL))"
      )

      signal=''
      if command -v iw &> /dev/null && [[ $eth_adapter =~ ^wl ]]; then
        signal=$(
          iw "$eth_adapter" link | grep -E 'signal: \-[[:digit:]]+ dBm' |
            grep -oE '\-[[:digit:]]+' || :
        )
        ssid=$(
          iw "$eth_adapter" link | grep -E 'SSID:' |
            sed 's/.*SSID: //' || :
        )
      fi

      payload_bw+=("$(
        tr -s ' ' <<- EOF
        "$eth_adapter": {
          $([ -n "$signal" ] && echo "\"signal\": \"$signal\",")
          $([ -n "$ssid" ] && echo "\"ssid\": \"$ssid\",")
          "rx": "$payload_rx",
          "tx": "$payload_tx"
        }
				EOF
      )") # N.B., EOF-line should be indented with tabs!

    fi

    rx_prev[i]=$rx
    tx_prev[i]=$tx

  done

  # Round-trip times

  if { : >&3; } 2> /dev/null; then

    # Read previous iteration's round-trip times into the payload
    payload_rtt=$(_readfd 3)

    (
      rtt_times=()

      # If the reporting interval allows it, wait a couple of seconds – on slow
      # systems, running this right away (ie, while the "main" loop is active)
      # has a noticeable impact on the round-trip times...
      sleep $((10#$SYSMON_INTERVAL * 2 / 10)) &
      wait $!

      for i in "${!rtt_hosts[@]}"; do

        rtt_host="${rtt_hosts[i]}"

        # In case of DNS errors, or unreachable hosts, ping can take quite a
        # while to complete – enforce a timeout (of roughly speaking two-seconds
        # more than needed) to ensure a predictable maximum duration.
        readarray -t result < <(
          timeout $((10#$SYSMON_RTT_COUNT + 1)) \
            ping -c "$((10#$SYSMON_RTT_COUNT))" \
            "$rtt_host" | grep 'rtt\|round-trip' |
            grep -oE '[[:digit:]]+\.[[:digit:]]{3}' || :
        )

        if [ -v result ] && [ -n "${result[1]}" ]; then

          rtt_times+=("$(
            tr -s ' ' <<- EOF
            "$(mqtt_json_clean "$rtt_host")":
              "$(printf '%4.3f' "${result[1]}")"
						EOF
          )") # N.B., EOF-line should be indented with tabs!

        fi

      done

      _join , "${rtt_times[@]}" >&3
      printf '\0' >&3
    ) &

  fi

  # APT & reboot-required

  payload_apt=()
  reboot_required=0

  if [ -v apt_check ]; then

    if [ -s "$apt_check" ]; then

      payload_apt+=("$(
        tr -s ' ' <<- EOF
        "count": "$(head -n 1 "$apt_check")",
        "upgradable": $(tail -n +3 "$apt_check")
				EOF
      )") # N.B., EOF-line should be indented with tabs!

    fi

    # Run apt-check and its processing once per hour

    if [ "$hourly" = true ]; then

      : > "$apt_check"

      # Fork it off so we don't block on waiting for this to complete
      (
        # shellcheck disable=SC1004
        apt_simulate=$(apt --simulate upgrade 2> /dev/null | gawk \
          'BEGIN{RS=""} ; match($0, \
            /The following packages will be upgraded:(.* not upgraded.)/,
          result){printf "%s", result[1]}')

        apt_upgrades=$(tail -n 1 <<< "$apt_simulate" | gawk \
          'match($0, /([0-9]+) upgraded,/, result){printf "%d", result[1]}')
        if [ -z "$apt_upgrades" ]; then
          apt_upgrades=0
          apt_summary="\"No packages can be upgraded.\""
        else
          apt_summary=$(head -n -1 <<< "$apt_simulate" | tr -d -s '\n' ' ')
          apt_summary=$(printf '%s\n\n%s' \
            "The following packages can be upgraded:" "${apt_summary:1:255}" |
            jq -R -s '.')
        fi

        printf '%s\n\n%s' "$apt_upgrades" "$apt_summary" > "$apt_check"
      ) &

    fi

    # Reboot-required

    if [ -f /var/run/reboot-required ]; then
      reboot_required=1
    fi

  fi

  # Construct payload

  payload=$(
    tr -s ' ' <<- EOF
    {
      "device-name": "$device_name",
      "uptime": "$uptime",
      "cpu-load": "$cpu_load",
      "disk-free": "$disk_avail",
      "mem-used": "$mem_used",
      $([ -v cpu_temp ] && echo "\"cpu-temp\": \"$cpu_temp\",")
      $([ -v status ] && echo "\"status\": \"$status\",")
      "bandwidth": {
        $(_join , "${payload_bw[@]}")
      },
      "rtt": {
        $payload_rtt
      },
      "reboot-required": "$reboot_required",
      "apt-packages": {
        $(_join , "${payload_apt[@]}")
      }
    }
		EOF
  ) # N.B., EOF-line should be indented with tabs!

  mosquitto_pub -h "$mqtt_host" \
    -t "$topic/state" -m "$payload" || true

  # Start publishing a "heartbeat" from the second iteration onward; during the
  # _first_ iteration, set up the exit-trap: This ensures errors during init
  # (and those while gathering the first set of metrics) are not trapped and
  # will leave the connected-state as "-1".

  if [ "$first_loop" = false ]; then

    mosquitto_pub -r -q 1 -h "$mqtt_host" \
      -t "$topic/connected" -m "$(date +%s)" || true

  else trap goodbye INT HUP TERM EXIT; fi

  first_loop=false

  # Track ticks and hourly-trigger

  ticks=$((ticks + 1))
  hourly=false
  if [ "$ticks" -gt "$hourly_ticks" ]; then
    hourly=true
    ticks=0
  fi

  sleep $((10#$SYSMON_INTERVAL)) &
  wait $!

done
