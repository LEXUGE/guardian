# Network

```text
application
  -> guest SOCKS5 127.0.0.1:1080
  -> socat TCP-to-UDS
  -> per-sandbox host UDS
  -> Guardian SOCKS5 CONNECT
  -> host TCP
```

The guest has no external network interface. Guardian creates the TCP socket, so the guest cannot inject IP packets.

## Transport boundary

The OCI spec mounts only that sandbox's State at `/run/guardian`. runsc `host-uds=open` permits host UDS nodes visible through sandbox mounts; it does not expose other host paths. The host State root is mode `0700`, State is `0711`, and `proxy.sock` is `0666`.

Host users cannot traverse the State root. The configured container user can reach only its mounted host socket.

## SOCKS proxy

```rust
pub struct Config {
    pub connect_timeout: Duration,
}

pub struct Proxy {
    listener: UnixListener,
    bind_path: PathBuf,
    config: Config,
}
```

```text
SOCKS5 no-auth -> CONNECT -> host TCP connect -> copy_bidirectional
```

Only `CONNECT` is supported. Unsupported commands return `CommandNotSupported`; connection failure returns `GeneralFailure`; timeout returns `TtlExpired`. Logs contain the bind path, target, and byte counts, not payloads.

`Proxy::run()` tracks at most 256 connection tasks and closes excess accepted sockets. Shutdown stops acceptance, aborts connections, joins their tasks, and returns.

## Guest configuration

Proxy environment variables point to `socks5h://127.0.0.1:1080`. libc name resolution does not use them, so Guardian supplies:

```text
getaddrinfo
  -> TCP 127.0.0.1:53
  -> socat SOCKS5-CONNECT
  -> upstream_dns:53
```

`resolv.conf` sets `nameserver 127.0.0.1` and `options use-vc`; `nsswitch.conf` selects `files dns`. UDP is unsupported.
