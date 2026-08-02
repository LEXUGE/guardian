# Podman backend

Podman owns images, OCI configuration, storage, signals, and persistent containers. Guardian uses rootless Podman with `runsc`; it does not build OCI bundles or use containerd.

## Types

See `guardian/rt/mod.rs`

`Context` is immutable and shared. `Sandbox` owns persistent identity; `Process` owns one attachment and all ephemeral resources.

## Identity and State

Each sandbox is identified by a UUID. Guardian stores its UUID in the Podman name and labels.

There is a central state directory, `/run/guardian` by default, for Guardian. Guardian holds an exclusive lock to the state root. For concurrent use cases, use an RPC server.

Under the state root, each sandbox gets its own state directory, identified by the sandbox UUID. Each State directory has mode `0711`:

| Path | Mode | Purpose |
|---|---:|---|
| `bootstrap.sh` | `0555` | guest relay setup |
| `resolv.conf` | `0444` | TCP-only DNS |
| `nsswitch.conf` | `0444` | resolver selection |
| `hosts` | `0444` | local hosts |
| `proxy.sock` | `0666` | per-execution SOCKS transport |

To create such a state directory:

```rust
Root::create(None)       // new UUID and State
Root::create(Some(id))   // create if absent; otherwise no-op
```

Dropping `State` removes its directory and ignores `NotFound`.

## Lifecycle

```text
init:   lock Root -> clear State
create: State -> podman create -> drop State -> Sandbox
start:  status -> State -> ProxyTask -> podman start --attach -> StdioTask -> ContainerTask
join:   ContainerTask -> StdioTask -> ProxyTask -> drop State
remove: podman rm --force
```

Creation uses temporary State because Podman validates bind mount sources. `start()` only accepts `Created` and `Stopped`, then recreates State idempotently. Setup failure releases only resources acquired by that operation. `Sandbox::remove()` is the only container removal path.

`ContainerTask` owns the child of `podman start --attach`. Child exit has priority over shutdown. On shutdown, it runs `podman stop` and waits for the child. Dropping `Process` requests this shutdown but does not await it.

`Process::join()` forwards `SIGINT` and `SIGTERM`, waits `stop_timeout`, then requests stop. If forwarding races with exit, an already-finished container task wins; other Podman errors are returned. `Process::stop()` does not handle signals.

On normal completion, `Process` awaits container exit, finishes I/O, stops the proxy, then removes State. On drop, its state, container, I/O, and proxy tasks shut down independently on a best-effort basis.

`StdioTask::Redirect` copies all three streams in one task. Its shutdown cancels stdin and drains stdout and stderr. `ProxyTask` is joined only during process cleanup, so proxy failure does not stop the container.

## Container configuration

On create, Guardian uses `--network=none`, `--init`, `--interactive`, `--http-proxy=false`, and `--cap-add=NET_BIND_SERVICE`. It mounts State and resolver files read-only, and adds `--tty` when requested. On create and start, it gives runsc `network=none`, `host-uds=open`, and `ignore-cgroups`. Start uses `--attach`, `--interactive`, and `--sig-proxy=false`.

The bootstrap starts the SOCKS and DNS relays, verifies their listeners, then `exec`s the command. Podman's init is PID 1. Guardian does not use privileged mode, host networking, broad host mounts, or cgroup resource enforcement. It does not override the image entrypoint.
