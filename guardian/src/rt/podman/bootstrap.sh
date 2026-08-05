#!/bin/sh
# Guest-side relay setup.
set -u

wait_for_tcp4_listener() {
    port="$1"
    pid="$2"
    while kill -0 "$pid" 2>/dev/null; do
        while read -r _ local _ state _; do
            if [ "$state" = "0A" ]; then
                case "$local" in
                    *:"$port") return 0 ;;
                esac
            fi
        done < /proc/net/tcp
        sleep 0.01
    done
    return 1
}

unset ALL_PROXY all_proxy HTTP_PROXY http_proxy HTTPS_PROXY https_proxy NO_PROXY no_proxy

if [ -S /run/guardian/proxy.sock ]; then
    ALL_PROXY=socks5h://127.0.0.1:1080
    all_proxy="$ALL_PROXY"
    HTTP_PROXY="$ALL_PROXY"
    http_proxy="$ALL_PROXY"
    HTTPS_PROXY="$ALL_PROXY"
    https_proxy="$ALL_PROXY"
    NO_PROXY=127.0.0.1,localhost
    no_proxy="$NO_PROXY"
    export ALL_PROXY all_proxy HTTP_PROXY http_proxy HTTPS_PROXY https_proxy NO_PROXY no_proxy

    socat TCP4-LISTEN:1080,bind=127.0.0.1,reuseaddr,fork \
        UNIX-CONNECT:/run/guardian/proxy.sock &
    socks_pid=$!
    wait_for_tcp4_listener 0438 "$socks_pid" || exit 125

    socat TCP4-LISTEN:53,bind=127.0.0.1,reuseaddr,fork \
        "SOCKS5-CONNECT:127.0.0.1:1080:${GUARDIAN_UPSTREAM_DNS}:53" &
    dns_pid=$!
    wait_for_tcp4_listener 0035 "$dns_pid" || exit 125
fi

exec "$@"
