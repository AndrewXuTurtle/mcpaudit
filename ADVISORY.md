# Advisory: `@modelcontextprotoco1/server-filesystem` impersonates the official MCP filesystem server

**Status:** live on npm at time of writing
**Discovered:** 2026-08-01
**Severity:** high (impersonation with forged provenance; no malicious code present yet)
**Affected package:** `@modelcontextprotoco1/server-filesystem@2026.1.14`
**Impersonates:** `@modelcontextprotocol/server-filesystem`

## Summary

An npm package published under a homoglyph of the official Model Context Protocol scope is a byte-identical copy of official release `2026.1.14`, republished under a name that differs from the real one by a single character:

```
@modelcontextprotoco1/server-filesystem     ← digit one
@modelcontextprotocol/server-filesystem     ← lowercase L
```

In most terminal and editor fonts these are difficult to tell apart, and in a copy-pasted config nobody looks.

## Evidence

Every compiled file in the impersonating package hashes identically to the official release of the same version number:

| File | SHA-256 match vs official `2026.1.14` |
| --- | --- |
| `dist/index.js` | identical |
| `dist/lib.js` | identical |
| `dist/path-utils.js` | identical |
| `dist/roots-utils.js` | identical |

The complete diff of `package.json` against the official release of the same version is one line:

```diff
- "name": "@modelcontextprotocol/server-filesystem"
+ "name": "@modelcontextprotoco1/server-filesystem"
```

The package also carries forged provenance metadata copied from the original:

- `author`: `Anthropic, PBC` (`https://anthropic.com`)
- `homepage`: `https://modelcontextprotocol.io`
- `repository`: `git+https://github.com/modelcontextprotocol/servers.git`
- `mcpName`: `io.github.modelcontextprotocol/server-filesystem`
- `bin`: `mcp-server-filesystem` — the same command name as the official package

Registry facts: published `2026-04-13` by npm user `eliav.livneh`; sole dist-tag `latest` = `2026.1.14`; roughly 21 downloads per month. The official package was at `2026.7.10` when this was written, so the impersonation is pinned to a months-old snapshot.

## Why this matters even though the code is clean

**There is no malicious code in this package today.** That is the finding, not a mitigating detail.

Publishing a clean, identical copy under a lookalike name is the setup phase of a rug pull. The package accrues installs while it is harmless and therefore unreportable. The payload arrives in a later version — and it arrives automatically for:

- anyone launching the server with `npx`, which resolves `latest` on every run,
- any config with an unpinned or range version,
- any CI job that reinstalls.

Because MCP servers hold whatever credentials you give them in a single process, and a filesystem server is typically granted broad directory access, the value of a successful rug pull here is high.

**Content-based scanners cannot detect this.** There is nothing malicious in the bytes to match against — the bytes are the official implementation. Signature and YARA-style analysis returns clean. Only provenance analysis, comparing the publisher and name against the known-good original, identifies it.

## Detection

```bash
npx github:AndrewXuTurtle/mcpaudit
```

`mcpaudit` reports this as `CRITICAL` via two independent checks — `MCP-SUP-006` (publisher scope impersonates a known scope) and `MCP-SUP-002` (package name visually identical to a known package) — before the server is ever run.

## If you have installed it

1. Remove it from every MCP config, and check each client separately — Claude Desktop, Claude Code, Cursor, Windsurf and VS Code keep independent files.
2. Reinstall `@modelcontextprotocol/server-filesystem` from the official documentation, character by character.
3. Rotate every credential that was in the environment of any MCP server, on the assumption that a future version could have taken them.
4. Pin the version. `npx` without a pin re-resolves `latest` on every launch.

## Method

Found while building fixtures for `mcpaudit`: the name was invented as a hypothetical example and turned out to exist. A systematic follow-up probed **790** homoglyph, deletion, doubling and transposition variants of the official scope across ten common server suffixes, and found exactly one live impersonation.

It does not appear in npm search results for `mcp server`, `modelcontextprotocol`, or related queries — a sweep of 1,070 distinct packages returned it zero times. It is reachable only by typo or by copied configuration.

## Disclosure

The package is publicly listed on npm and contains no exploit code, so this advisory does not enable an attack that the package does not already permit. It is named here so users can check their configs and avoid it. It should be reported to npm support for namespace impersonation under their dispute process.
