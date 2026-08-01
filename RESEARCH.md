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

---

## Update, 2026-08-02: the sweep that found nothing, and why that mattered

I widened the impersonation sweep to **1,267 candidate names** across the fourteen
highest-traffic MCP packages — homoglyph substitutions, deletions, doublings, transpositions
and hyphen-stripping, against both scopes and package names.

Three names existed. Only one is an impersonation.

| Package | First published | Verdict |
| --- | --- | --- |
| `@modelcontextprotoco1/server-filesystem` | 2026-04-13 | **Impersonation** — byte-identical to official 2026.1.14 |
| `cp-remote` | 2014-03-10 | Innocent — a `child_process` runner, twelve years old |
| `mp-remote` | 2020-12-11 | Innocent — abandoned, predates MCP by four years |

`cp-remote` and `mp-remote` are each one deletion away from `mcp-remote`. They are also
older than the Model Context Protocol itself. They are collisions, not squats.

My own scanner flagged both as `CRITICAL` typosquats.

**Impersonation cannot run backwards in time.** If a package was published before the
package it supposedly imitates, the resemblance is a coincidence — and registry creation
dates make that decidable rather than a judgement call. mcpaudit now resolves the creation
date of the package a name resembles and drops the finding when the accused is older.

When the original cannot be resolved, the finding is kept. Unknown provenance should fail
loud, not quiet.

This is the second false-positive class this project has found in itself in two days, and
both came from the same root cause: **matching shape while ignoring context.** The first
ignored what happened to a value one line later. This one ignored what happened four years
earlier.

An edit distance is not evidence of intent. A scanner that treats it as such will eventually
accuse a maintainer who did nothing, and being loudly wrong about a person is worse than
being quietly wrong about a string.

---

## Update, 2026-08-02 (later): PyPI, and a negative result worth publishing

Half the MCP ecosystem is Python, launched through `uvx`. mcpaudit skipped all of it — it
returned early on any `pypi:` package, so Anthropic's own `mcp-server-fetch` and
`mcp-server-git` received no supply-chain analysis at all. That gap is now closed.

One detail decided the design. PyPI applies [PEP 503](https://peps.python.org/pep-0503/)
normalisation: runs of `-`, `_` and `.` are equivalent and case is ignored, so
`mcp_server_fetch` and `mcp-server-fetch` are not similar names — they are *the same
project*. A scanner comparing raw strings would report a package as a typosquat of itself.

I then swept **278 candidate names** across the six most-used Python MCP packages.
Seventeen exist. **None is an impersonation.**

Most are ordinary packages that predate the Model Context Protocol entirely: `mc` is a
memcached client, `mpc` a differentiable solver for PyTorch, `mkp` a Check_MK archive tool
from 2015. They collide with MCP names by coincidence, not design.

The closest call was `mcp-server-fetch2`, whose author field reads
`"Anthropic, PBC., J Muzhen"` and whose summary is copied verbatim from the official
package. I downloaded and read it. It is a **legitimate fork** — real source, added
dependencies (`markitdown`, `cachetools`), Anthropic's own security caution preserved in the
README, and no suspicious behaviour anywhere in it.

So it is not an advisory. What it *is* is a provenance problem: it retains a first-party
author string while being unaffiliated, and publishes no repository or homepage URL, so a
user cannot trace where its code came from. mcpaudit reports that as `HIGH` —
*verify this before trusting it* — not `CRITICAL`. Getting that severity right matters more
than the finding does. A fork with untidy metadata is not a supply-chain attack, and
publishing it as one would be unfair to someone who wrote real software.

### The result

The npm homoglyph attack has **no PyPI counterpart in this ecosystem**. One live
impersonation on npm; zero on PyPI across 278 probes.

A negative result is still a result. "We looked and found nothing" is only worth reading
when you can say precisely how hard you looked — 278 names, six targets, four variant
classes — and when the tool doing the looking has had its false positives published rather
than buried.

---

## Update, 2026-08-02: two corrections, one of them to my own credit claim

### The typosquat was already known

I searched GitHub for other code referencing `@modelcontextprotoco1` and found two independent
trackers:

- **Microsoft Defender** ships a signature (`ALFTrojanAIAgentMCPSupplyChainA`) that reads MCP
  config files — `mcp.json`, `claude_desktop_config.json`, `settings.json`, `openclaw.json` —
  and matches the lookalike scope string, returning a detection.
- **mcpshield** lists it in its vulnerability database as a critical scope typosquat.

My write-up implied discovery. It was an independent rediscovery, and the README and advisory now
say so.

Losing the "found it first" line costs less than it looks. Microsoft detecting on the *identifier
in a config file*, rather than on anything inside the package, is the same conclusion this project
reached from the other direction: there is nothing in the payload to detect, because the payload
is the official implementation. Independent corroboration is worth more than a novelty claim, and
a novelty claim that does not survive a search is worth less than nothing.

### The accusation I nearly published

While reading mcpshield's database I noticed it lists `@anthropic-ai/mcp-server-git` as a *"fake
`@anthropic-ai` scope"*. `@anthropic-ai` is Anthropic's real scope — `@anthropic-ai/sdk` alone
does 113 million downloads a month. Four other entries named typosquats that returned 404 on npm,
and one carried `verified: true` alongside a CVE ID.

The obvious reading was a security tool shipping fabricated vulnerability data, and I was one step
from opening an issue saying so.

I checked first. **CVE-2025-68145 is real** — it resolves in NVD and in GitHub's advisory
database, a genuine path-validation bypass in `mcp-server-git`. And the packages returned 404
because `mcp-server-git` lives on **PyPI**, not npm. I had queried the wrong registry and read the
result as evidence of fabrication.

So the database is not fabricated, the issue does not get filed, and the naming inconsistency is
sloppiness rather than invention. Worth recording plainly: I was about to publish a public
accusation against a six-star project, on the strength of 404s from a registry the packages were
never on — while shipping a competing scanner. Being right about the typosquat earlier does not
make the next hypothesis right.

Three false-positive classes found in this tool now, and this one was in the operator rather than
the code. It is the same failure as the other two: a signal read without the context that explains
it.

---

## Update, 2026-08-02: two confirmed-malware Claude Code typosquats, and the check I was missing

Reading Microsoft's Defender signature paid off in a way I did not expect. Besides the scope
typosquat I already knew about, it matches two other strings: `cloude-code` and `cloude`.

Both exist on npm. Both resolve to version `0.0.1-security` with **zero maintainers**, and the
package contents are a two-file placeholder whose README says, verbatim:

> This package contained malicious code and was removed from the registry by the npm security
> team. A placeholder was published to ensure users are not affected in the future.

So these were live typosquats of `@anthropic-ai/claude-code` — 38 and 42 downloads a month even
now, as tombstones — and npm has already taken them down.

**mcpaudit could not detect this at all.** That is a worse gap than it first appears, because it
is the single highest-confidence signal available anywhere in this problem space. Every other
check in this tool is an inference: *this looks over-scoped*, *this name looks close to that one*,
*this code could exfiltrate*. A security-holding placeholder is not an inference. It is the
registry stating that the package you configured contained malicious code.

`MCP-SUP-007` now reports it as `CRITICAL` / `certain`, and says the thing that actually matters:
if it ever ran, treat it as a compromise and rotate every credential it could reach — the
environment it was handed, plus anything readable from the directories it was given.

The detection is npm-controlled and unambiguous — version `0.0.1-security`, or the description
`security holding package` — so it carries no false-positive risk. Verified against real
takedowns, with the legitimate `@anthropic-ai/claude-code` asserted clean in the same test.

Two lessons worth keeping:

**Threat intelligence beats cleverness.** I spent two cycles generating thousands of homoglyph
permutations and found nothing new. Reading one vendor's published indicator list took minutes and
produced two confirmed-malware packages plus a missing check. The permutations were guessing what
an attacker *might* do; the signature recorded what one *did*.

**A removed package is still in configs.** npm's takedown protects installs, not the configuration
files pointing at it. Anyone who added `cloude-code` in February still has that line, and still
has whatever credentials it saw. Nothing tells them — which is exactly the job of a config auditor.

---

## Update, 2026-08-02: I checked whether a 91k-star list recommends malware. The answer changed what I publish.

Having assembled 220 MCP-named packages carrying malware advisories, the obvious use was to
cross-reference them against the lists people actually read. If a popular list points at a package
a registry removed for malware, that is urgent and worth telling the maintainer.

I extracted every package reference from five `awesome-mcp-*` lists — 548 of them in
`punkpeye/awesome-mcp-servers` alone, at 91,684 stars — and got exactly one match: `lokal-mcp`,
installed by that list as `npx lokal-mcp`.

The advisory looked damning. **GHSA-9rg3-p529-qp32**, severity critical, "Malicious code in
lokal-mcp (npm)", published 2026-07-27, **not withdrawn**, affected range `= 0.4.0` with no patched
version — and `0.4.0` is exactly what npm serves today.

Then I read the package.

18 KB. Three files. No install hooks. No `child_process`, no `eval`, no `new Function`, no `atob`,
no base64 blobs. One use of `process.env`, reading its own `LOKAL_URL` setting. One outbound host:
`rettfrabonden.com`, its own documented API. A tidy MCP server for finding Norwegian farm shops.

I cannot prove a negative from static reading, but there is nothing here that resembles the
advisory. It looks like a false positive, and I am not going to tell a 91,000-star repository that
an innocent developer's package is malware on the strength of an automated flag my own inspection
contradicts.

### The part that mattered was about my own page

The Trust Index was publishing those 220 names under the heading **"Confirmed-malicious MCP
packages"**, with the line *"each was examined by a registry security team and removed"*.

For `lokal-mcp` that is false. It was not removed — it is live, maintained, and by all appearances
fine. I had automated the exact failure this project keeps documenting in other tools: taking a
signal as a verdict, at scale, on a public page, about named people.

Fixed in three ways. The heading now reads *"MCP packages with published malware advisories"*. The
section leads with the caveat and names `lokal-mcp` as a worked example of why a row here is a
prompt to look rather than a conclusion. And withdrawn advisories are now filtered out, so a
retraction by GitHub removes the entry instead of preserving an accusation its author took back.

Note the asymmetry that makes this worth writing down. Where npm has replaced a package with a
`0.0.1-security` placeholder, the registry has *acted* — that is a fact, and `MCP-SUP-007` reports
it as certain. An advisory alone is a *claim*, and claims from automated systems are wrong
sometimes. Those two things had been flattened into one table under one confident heading.

Four false-positive classes found in this project now. This is the first one I shipped to
production before catching it.

---

## Update, 2026-08-02: what actually became of 220 flagged MCP packages

A list of package names carrying malware advisories is less useful than it looks, and more
harmful than it looks. I resolved every one of the 220 against the registry and against its own
advisory's version range.

| Outcome | Count | Share |
| --- | ---: | ---: |
| Removed from the registry | 73 | 33.2% |
| Replaced by npm with a security placeholder | 64 | 29.1% |
| **Already remediated** — published version is outside the advisory range | **62** | **28.2%** |
| Affected version still published | 10 | 4.5% |
| Undetermined | 11 | 5.0% |

**62% of the registry acted.** Removal or a security placeholder is a fact, not an inference — the
registry did something, and `MCP-SUP-007` treats that as certain.

**28% had already been fixed by their maintainers, and my index was misrepresenting all of them.**
An advisory names a *version range*. Where the maintainer has since published outside it, the
package on the registry today is not the package the advisory describes:

| Package | Published now | Advisory covers |
| --- | --- | --- |
| `mcp-echarts` | 0.7.1 | `= 0.8.1` |
| `mcp-mermaid` | 0.4.1 | `= 0.5.1` |
| `@antv/mcp-server-antv` | 0.1.8 | `= 0.2.8` |

Those are AntV's visualization servers. The pattern — current version *below* the flagged one — is
a compromise handled properly: a malicious release published, then pulled, leaving the last good
version serving. Listing those maintainers under a heading about malware, with no indication they
had already cleaned up, was a smear produced by a cron job.

**Only 10 of 220 (4.5%) still publish an affected version.** That is the set worth caution — and
also where a wrong advisory does the most damage, which is why the page now says to read the
advisory before concluding anything. One of those ten is `lokal-mcp`, whose code I read in the
previous session and found unremarkable.

The index is now grouped by outcome rather than presented as one flat table, and the remediated
section states plainly that it is listed for completeness and should not be read as a warning.

### The general lesson

Every correction in this project has the same shape: **a signal is not a verdict, and aggregating
signals at scale industrialises whatever error is in them.** A regex that ignores the next line.
An edit distance that ignores publication dates. An advisory that ignores which version is
actually being served.

The difference here is the blast radius. A false positive in a CLI wastes one person's afternoon.
A false positive on a published index, regenerated nightly and indexed by search engines, is a
durable public claim about somebody's work. Building the automation was the easy part; deciding
what it is entitled to assert took four corrections.
