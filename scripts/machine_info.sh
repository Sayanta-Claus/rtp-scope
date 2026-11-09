#!/usr/bin/env bash
# machine_info.sh -- print the facts needed to interpret a benchmark result.
# CPU model, core count, RAM, kernel and OS, all read from the running machine.
cpu="$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ *//')"
mem_kb="$(grep -m1 MemTotal /proc/meminfo | awk '{print $2}')"
echo "cpu      : ${cpu:-unknown}"
echo "cores    : $(nproc) logical"
echo "memory   : $((mem_kb / 1024)) MiB"
echo "kernel   : $(uname -sr)"
echo "os       : $(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME")"
if grep -qi microsoft /proc/version 2>/dev/null; then echo "note     : running under WSL2 (virtualised; /mnt/* is a network-backed filesystem)"; fi
