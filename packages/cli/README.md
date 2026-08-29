# packages/cli

The `agentguard` CLI ships **inside the `agentguard` package**
([`../sdk-python`](../sdk-python)) so that `pip install agentguard` gives you both
the SDK and the command — see [`../../docs/SDK.md`](../../docs/SDK.md).

This directory is reserved for a future standalone CLI distribution (extra
commands, shell completions, self-update) if the CLI ever needs to version
independently of the SDK. Nothing lives here yet.
