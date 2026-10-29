# `node2shell-inventory-scanner`

Local inventory triage for `Node2Shell`, `CVE-2026-111497`. It finds every copy of the broken `Brotli` decoder already sitting on your machine or in your project, and grades it. It never touches the network, never sends a payload, never probes a server.

## `The flaw`

| `Detail` | `Value` |
| --- | --- |
| `CVE` | `CVE-2026-111497` |
| `Also called` | `Node2Shell`, `HTTP2Shell`, `Broccoli2Shell` |
| `Bug` | `Out-of-bounds write` in the `Google Brotli` decoder (`c/dec/decode.c`) |
| `Impact` | `Process crash`, `memory disclosure`, or `remote code execution` when an app decompresses attacker-controlled `Brotli` data |
| `Severity` | `9.2` critical (`CVSS 4.0`, `Google` as `CNA`) |
| `Exploitation` | `CISA KEV`, added `2026-10-27`, federal due date `2026-11-10` |

`Brotli 1.0.3` through `1.2.0` is affected. `Node.js` bundles that decoder, so any `Node` process that decompresses `Brotli` data it did not create is in scope: a request body through `Express 5` / `body-parser 2.x`, which decode `br` bodies by default, or a fetched response through `fetch()` / `node:zlib` from a server you do not control. Just serving `Brotli`-compressed responses does not invoke the decoder, and a bare `http` server that never decompresses a body is not reachable this way. A version in range is triage, not proof your app is reachable. Check whether untrusted `Brotli` data ever reaches the process.

Two source disagreements, and what this scanner follows. On severity, `Node.js` rates the issue `High`, `Google`'s `CVE` record scores it `9.2` critical, and `Singapore CSA` cites `9.8` under `CVSS 3.1`. This scanner follows the `CNA` score, `9.2`, and says so. On exploitation, `ELLIO`'s honeypots recorded exploit traffic on `2026-10-26` and `ELLIO` says the exploit gets a shell on vulnerable builds in its lab, while other reports of the same observed traffic say that attempt crashed the process instead of getting a shell. This scanner follows `CISA KEV`: exploitation is confirmed in the wild, the details are not public, and the observed-attempt argument does not change the patching advice.

## `Fixed versions`

| `Line` | `Fixed in` |
| --- | --- |
| `Node.js 22.x` | `22.23.4` |
| `Node.js 24.x` | `24.22.1` |
| `Node.js 26.x` | `26.12.1` |
| `Node.js 20.x`, `23.x`, `25.x` and older | `No fix`, end of life, move to a supported line |
| `Bun` | `1.4.4` |
| `Brotli` library | `1.0.10`, `1.1.1`, `1.2.1` for their lines |
| `Python brotli` | `1.2.1` |
| `Python brotlicffi` | `1.2.1.0` |

Updating the runtime is the fix. Rebuild container images from a fresh base tag, redeploy, restart the process, then verify the running version. A pinned image tag stays vulnerable until it is rebuilt.

## `What it checks`

- `node` and `bun` binaries on `PATH`, plus any `--scan-dir` tree (`nvm` installs included)
- `Python brotli` / `brotlicffi` in the current environment
- `.nvmrc` pins, `package.json` engines and body-parsing dependencies, and `Dockerfile` `node:` base-image tags in a project tree

Each finding gets a verdict: `VULNERABLE`, `FIXED`, `EOL_NO_FIX`, `UNKNOWN`, or `INFO` for project notes like `Express 5` body decoding. `Docker` tags that pin a line but not a patch (`node:24`) grade `UNKNOWN`, because the patch they resolve to depends on when the image was built.

## `What it never does`

No network requests. No `Brotli` payloads, crafted or otherwise. No probing of remote servers, no `23 MB` probes, no exploit traffic. It reads version strings off your own disk and stops.

## `Why this, when a network scanner already exists`

`Assetnote`'s free `node2shell-scanner` (released `2026-10-25`) probes `HTTP` endpoints from the network, route by route. That is a good tool for the server side, and it is not this tool. It says itself it does not find fetchers or `Python` clients, and one clean route does not clear the others. This scanner covers the half it misses: the runtimes, libraries, and image pins sitting on disk, including the fetcher that decodes responses from servers you do not control. Use both. A clean network probe plus a clean inventory is a much stronger statement than either alone.

## `Grading`

| `Finding` | `Severity` |
| --- | --- |
| `Node` below its line's fixed patch, `Bun` below `1.4.4`, `Brotli` in `1.0.3`-`1.2.0`, `brotlicffi` below `1.2.1.0` | `VULNERABLE` |
| `Node` on an end-of-life line | `EOL_NO_FIX`, counts as vulnerable, there is no patch coming |
| `Node` at or past its line's fixed patch, and fixed `Bun` / `Brotli` / `brotlicffi` | `FIXED` |
| `Floating Docker tag`, `line-only pin`, `unparseable version`, or a `Node` line newer than `26.x` | `UNKNOWN`, not clean |
| `Express 5` / `body-parser 2.x` present, `engines.node` noted | `INFO`, exposure context only, not a verdict |

## `Usage`

```
# Inventory this machine: PATH runtimes, Python packages, current project
python3 node2shell_inventory_scanner.py

# Inventory a project tree, machine-readable output
python3 node2shell_inventory_scanner.py --scan-dir /srv/myapp --json

# Scan a tree only, without PATH runtimes
python3 node2shell_inventory_scanner.py --scan-dir ~/projects/api --no-path

# Tests (fake binaries and fake project trees only, no network)
python3 -m unittest discover -s tests -v
```

Exit codes: `0` = nothing vulnerable found, `2` = vulnerable or end-of-life finding, `1` = scan error. `UNKNOWN` does not change the exit code, but it is not clean. Confirm those items another way before closing them.

## `Honest caveats`

- A version in range is triage, not proof of exploitability. The app must actually decompress attacker-controlled `Brotli` data for this flaw to be reachable.
- For `Bun`, the fix version `1.4.4` is well attested, but the exact affected floor for `Bun` is not stated in the advisory text this scanner verified, so anything below `1.4.4` grades `VULNERABLE` conservatively.
- A `Node.js` installed from a distribution package may use the system `Brotli` library instead of the bundled copy. The scanner flags distribution paths with a note: check the distribution `brotli` package too.
- `Docker` tags lie by omission. `node:24` built before the fix and `node:24` built after it share a tag. Rebuild with `--pull` and verify the running version.
- This scanner does not inventory vendored `Brotli` copies inside other binaries (`.NET`, `Envoy`, `Istio`, firmware, data tools). Those need their vendors' advisories.
- No exploit code is included, linked, or reproduced here.

## `References`

- `Node.js` October 2026 security releases (fixed `22.23.4`, `24.22.1`, `26.12.1`)
- `CVE-2026-111497` record (`Brotli 1.0.3`-`1.2.0` affected, fixed `1.0.10` / `1.1.1` / `1.2.1`, `CVSS 4.0 9.2`)
- `CISA KEV` entry (added `2026-10-27`, due `2026-11-10`, ransomware use unknown)
- `Assetnote node2shell-scanner` (network-side check this tool deliberately complements, not duplicates)

## `Thanks to`

- The `Node.js` maintainers for the advisory and the fixed releases
- The `Brotli` maintainers for the decoder fix
- `ELLIO`, `Imperva`, and everyone publishing `Node2Shell` detection research

## `Disclaimer`

Built for defensive triage and authorized testing only. Scan only systems you own or are authorized to test. The authors are not responsible for misuse.

> Research by `Vineeth Kumar` (`foxcornlab`). Found a bug or want a feature, open an `issue`.
