# I audited the 30 most-installed MCP servers. Then I audited my own scanner.

*2026-08-02*

I built [mcpaudit](https://github.com/AndrewXuTurtle/mcpaudit) because published testing put
YARA-style MCP scanners near a **78% false-positive rate**, and a tool that is wrong four
times in five gets uninstalled inside a week. Precision, not recall, is the problem worth
solving.

Then I pointed it at the thirty most-installed MCP server packages on npm — about 24 million
downloads a month between them — and it reported two CRITICAL findings.

Both were wrong. Mine.

## The false positive

`@notionhq/notion-mcp-server` (705k downloads/month) and `@delorenj/mcp-server-trello`
(122k/month) were both flagged for *serialising the entire environment* — the signature of
credential exfiltration. Here is what the scanner actually matched:

```js
exports.inspectOpts = Object.keys(process.env).filter((key) => {
  return /^debug_/i.test(key);
});
```

That is the [`debug`](https://www.npmjs.com/package/debug) package reading its own `DEBUG_*`
configuration. It is vendored into thousands of dependency trees. It is not exfiltration; it
is one of the most common lines of JavaScript in existence.

My pattern matched `Object.keys(process.env)` and stopped reading. The very next call
*filters* the result down to variables the library owns. Shape matched; meaning did not.

This is exactly the failure I wrote the tool to avoid, reproduced on my own CRITICAL tier at
a 100% rate, on day two.

## The fix: context gates, not better patterns

The instinct is to write a tighter regex. That is the treadmill that produced the 78% number
in the first place — each new pattern is narrower, and each still reads shape rather than
meaning.

Two gates instead, applied to a 600-character window around every match:

**Refutation.** A known-benign idiom in range kills the finding outright.

```js
refute: /Object\.(keys|entries)\s*\(\s*process\.env\s*\)\s*\.\s*(filter|find|some|every)/
```

**Egress.** Capturing the environment is only alarming if it can leave the process. No
`fetch`, no `axios`, no socket in range, no finding.

```js
needsEgress: true
```

Reading data is not stealing data. A scanner that cannot tell the difference will flag every
program that has ever read its own configuration.

The same bug class was waiting in the credential-path check. It looks for references to
`~/.ssh/id_rsa` and `~/.aws/credentials` — but a *security-conscious* filesystem server
denylisting exactly those paths would have been flagged for protecting you. That one now
refutes on guard language (`deny`, `blocklist`, `refuse`, `sensitive`).

Result across the same thirty packages:

| | Before | After |
| --- | --- | --- |
| Critical | 2 | **0** |
| High | 1 | 1 |

Both suppressions are pinned by regression tests that assert the checks *still fire* on
genuinely malicious code — environment capture next to a `fetch`, credential paths without
guard language, `eval` of a fetched payload. Silencing an alarm and fixing an alarm look
identical until you test the other direction.

## What the thirty packages actually look like

**They are clean.** Zero critical findings, one high: `@azure/mcp` (471k downloads/month)
runs a `postinstall` script. That is verifiable from registry metadata and is not an
accusation — install hooks are legitimate and common. It is worth knowing because a
`postinstall` executes when the package is *fetched*, before the server is ever started and
before any tool description is reviewed. With `npx` and an unpinned version, that is every
launch.

A note on what I deliberately did **not** report: my scan harness configured all thirty
servers as `npx -y <package>` with no version pin, so every one produced an "unpinned
version" finding. That is a fact about my test config, not about those packages. Reporting
"30 of 30 top MCP servers are unpinned" would have been a true-looking sentence measuring
nothing but my own fixture.

## The real finding is elsewhere

The dangerous package in this ecosystem is not in the top thirty. It is
`@modelcontextprotoco1/server-filesystem` — digit one instead of lowercase L — a
**byte-identical copy of Anthropic's official release 2026.1.14**, republished under a
homoglyph scope with forged `author: "Anthropic, PBC"` metadata.

There is no malicious code in it. That is what makes it worth writing about: it is the setup
phase of a rug pull. Publish something clean and identical, accumulate installs while it is
harmless and unreportable, ship the payload in a later version that every `npx` user picks
up automatically.

**No content scanner can catch it, mine included**, because there is nothing bad in the
content — the content *is* the official implementation. Every byte hashes identically. Only
provenance catches it: comparing publisher and name against the known-good original.

Full writeup in [ADVISORY.md](ADVISORY.md). I probed 790 homoglyph variants of the official
scope and found exactly one live impersonation.

## The lesson

Security scanners are judged on what they catch. They are *abandoned* on what they get wrong.
The industry measures the first and ships the second, which is how you arrive at 78%.

False positives in mcpaudit are treated as bugs of the same severity as misses. This document
exists because the tool had two, and hiding them would have made every other claim in the
README worth less.

```bash
npx github:AndrewXuTurtle/mcpaudit
```
