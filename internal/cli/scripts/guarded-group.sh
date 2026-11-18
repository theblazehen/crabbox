read_guard() {
    read -r guard started group extra 2>/dev/null <"$directory/.crabbox-owned" || return 1
    case $guard:$started:$group in *[!0-9:]*|:*|*::*|*:) return 1;; esac
    [ -z "${extra:-}" ]
}
valid_guard() {
    local current
    current=$(cat "$directory/.crabbox-owned" 2>/dev/null) || return 1
    [ "$current" = "$guard $started $group" ] &&
        [ "$(identity "$guard")" = "$group $started" ]
}
group_exists() {
    local diagnostic
    diagnostic=$(LC_ALL=C kill -0 -- "-$group" 2>&1) && return 0
    # Only ESRCH proves absence. Permission failure must retain evidence too.
    [[ "$diagnostic" != *": (-$group) - No such process" ]]
}
group_has_workload() {
    local processes pid pgid state extra guard_seen=0
    # The guard ignores TERM and reserves the group identity. Ignore it and
    # exited zombies, but retain the grace if the snapshot is unavailable.
    processes=$(LC_ALL=C ps -e -o pid= -o pgid= -o stat= 2>/dev/null) || return 0
    while read -r pid pgid state extra; do
        case $pid:$pgid in *[!0-9:]*|:*|*:) return 0;; esac
        [ -n "$state" ] && [ -z "$extra" ] || return 0
        [ "$pgid" = "$group" ] || continue
        if [ "$pid" = "$guard" ]; then guard_seen=1; continue; fi
        case $state in Z*|X*) ;; *) return 0;; esac
    done <<EOF
$processes
EOF
    [ "$guard_seen" = 0 ]
}
# Milliseconds on a clock that never runs ahead of real time, plus the
# resolution of the source that supplied it. Bash 5 exposes EPOCHREALTIME;
# older interpreters read the kernel's uptime (Linux and WSL); the last resort
# is whole seconds, which can only lengthen the bound.
now_ms() {
    local stamp fraction
    clock_resolution_ms=1
    if [ -n "${EPOCHREALTIME:-}" ]; then
        stamp=${EPOCHREALTIME//[!0-9]/}
        clock_ms=$((10#$stamp / 1000))
        return 0
    fi
    if IFS=. read -r stamp fraction 2>/dev/null <"/proc/uptime"; then
        fraction=${fraction%% *}
        case $stamp:$fraction in
        *[!0-9:]*|:*|*:) ;;
        *)
            if [ "${#fraction}" = 2 ]; then
                clock_resolution_ms=10
                clock_ms=$((10#$stamp * 1000 + 10#$fraction * 10))
                return 0
            fi
            ;;
        esac
    fi
    clock_resolution_ms=1000
    clock_ms=$(($(date +%s) * 1000))
}
# A grace deadline in milliseconds. The clock's own resolution is added so a
# coarse source can never cut the grace short.
grace_deadline() {
    now_ms
    deadline_ms=$((clock_ms + grace_ms + clock_resolution_ms))
}
cleanup_group() {
    # Keep the witness alive through TERM. Revalidate both its immutable
    # process identity and the published record before the final KILL.
    valid_guard || return 1
    kill -TERM -- "-$group" 2>/dev/null || return 1
    # The grace is elapsed time, not a count of polls: a loaded host must not
    # stretch it, and work that already finished waits nothing.
    grace_deadline
    while now_ms && [ "$clock_ms" -lt "$deadline_ms" ] && group_exists && group_has_workload; do
        sleep .1
    done
    valid_guard || return 1
    kill -KILL -- "-$group" 2>/dev/null || return 1
    wait "$leader" 2>/dev/null || :
    wait "$guard" 2>/dev/null || :
    grace_deadline
    while now_ms && [ "$clock_ms" -lt "$deadline_ms" ] && group_exists; do sleep .1; done
    ! group_exists || return 1
    [ "$(cat "$directory/.crabbox-owned" 2>/dev/null)" = "$guard $started $group" ]
}
