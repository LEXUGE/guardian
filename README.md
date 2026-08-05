# Guardian

Guardian is a secure, auditable computing environment for AI agents.

While it aims to support generic sandbox backends, currently the implementation focuses on running OCI containers using rootless gVisor and a network proxy through Unix domain socket.

It aims to be simple so you could review the code and customize.

> [!WARNING]
> The project is currently a prototype. Currently the network proxy is "log-only" and enforces no filtering. In particular it's possible for guest to access local services. Modify the code if you need specific enforcement.

## Quickstart

You would need:
- Linux with rootless Podman and `runsc`
- an image containing `socat` without an `ENTRYPOINT` (see [example image](examples/demo-image)). Guardian preserves image entrypoint semantics and supplies its bootstrap as the container command.

```sh
nix develop
podman build -t guardian-demo examples/demo-image
cargo run -p guardian-cli -- run guardian-demo --ephemeral -- curl https://example.com
```

Guardian CLI exposes several commands:
```
Commands:
  create  Create a persistent sandbox
  run     Create, start, and attach to a sandbox
  start   Start and attach to a sandbox
  status  Print sandbox status
  kill    Force-stop a sandbox
  remove  Delete a sandbox
  help    Print this message or the help of the given subcommand(s)
```

> [!NOTE]
> `create` and later `start` must use the same `--state-root`; the default is `$XDG_RUNTIME_DIR/guardian`.

Each sandbox is identified through an UUID which you would need to `start`, `status`, `kill`, and `remove`:

```sh
id=$(guardian create guardian-demo -- /bin/sh)
guardian start "$id"
guardian status "$id"
guardian kill "$id"
guardian remove "$id"
```

Some useful options:
- Pass `--ephemeral` to `run` to remove its sandbox after the attached process exits.
- Pass `--name NAME` to `create` or `run` to use that exact Podman container name. The default is `guardian-UUID`.
- Pass `--mount SPEC` repeatedly to forward Podman mount specifications at sandbox creation. For example, `--mount type=bind,source=./workspace,destination=/workspace` persists guest writes in `./workspace`.
- Pass `--volume SPEC` repeatedly to forward Podman volume specifications at sandbox creation. For example, `--volume ./workspace:/workspace` persists guest writes in `./workspace`.

Guardian's structured logs are appended to `guardian.jsonl`; use `--log-file` and `RUST_LOG` to configure them.

## Documentation
See the [runtime interface](docs/interface.md), [Podman backend](docs/podman.md), and [network](docs/net.md) documentation.
