# Guardian

Guardian is a secure, auditable computing environment for AI agents.

While it aims to support generic sandbox backends, currently the implementation focuses on running OCI containers using rootless gVisor and a network proxy through Unix domain socket.

It aims to be simple so you could review the code and customize.

> [!WARNING]
> The project is currently a prototype. Currently the network proxy rejects any remote with a reserved/special purpose IP address. Use `--network=none` to completely disable network if required.

## Quickstart

You would need:
- Linux with rootless Podman and `runsc`.
- Podman socket enabled.
- an image containing `socat` without an `ENTRYPOINT` (see [example image](examples/demo-image)). Guardian preserves image entrypoint semantics and supplies its bootstrap as the container command.

```sh
nix develop
podman build -t guardian-demo examples/demo-image
cargo run -p guardian-cli -- run --ephemeral guardian-demo curl https://example.com
```

Guardian CLI exposes several commands:
```
Usage: guardian [OPTIONS] <COMMAND>

Commands:
  create  Create a persistent sandbox
  run     Create a sandbox, run one command, then stop the sandbox
  start   Start a sandbox and own it until interrupted
  exec    Execute one command in a running sandbox
  status  Print sandbox status
  kill    Force-stop a sandbox
  remove  Delete a sandbox
  list    List Guardian-managed containers as JSON
  help    Print this message or the help of the given subcommand(s)
```

> [!NOTE]
> `create` and later `start` must use the same `--state-root`; the default is `$XDG_RUNTIME_DIR/guardian`.

Each sandbox has one foreground `start` owner and zero or more concurrent `exec`
commands. In one terminal:

```sh
id=$(guardian create guardian-demo)
guardian start "$id"
```

While that owner is running, another terminal can execute commands:

```sh
guardian exec "$id" curl https://example.com
guardian exec -t "$id" bash
guardian status "$id"
```

Interrupt `guardian start` to stop the sandbox, then remove it with
`guardian remove "$id"`.

Some useful options:
- Pass `--network=<open|none>` to enable/disable Unix domain socket based networking.
- Pass `--ephemeral` (default to true) to `run` to remove its sandbox after the command exits.
- Command stdin, stdout, and stderr are inherited. Pass `-t`/`--tty` to
  allocate a guest terminal.
- Pass `--name NAME` to `create` or `run` to specify exact Podman container name.
- Pass `--mount SPEC` repeatedly to forward Podman mount specifications at sandbox creation. For example, `--mount type=bind,source=./workspace,destination=/workspace` persists guest writes in `./workspace`.
- Pass `--volume SPEC` repeatedly to forward Podman volume specifications at sandbox creation. For example, `--volume ./workspace:/workspace` persists guest writes in `./workspace`.
- Pass `--gvisor-overlay2 VALUE` to configure gVisor's filesystem overlay; it defaults to `root:self`.

Guardian's structured logs are appended to `<STATE_ROOT>/log.jsonl`; use `--log-file` and `RUST_LOG` to configure them.
