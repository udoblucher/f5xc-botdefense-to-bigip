# xcbot — F5 XC Bot Defense → BIG-IP configuration

Fetch a Bot Endpoint Policy from F5 Distributed Cloud, save it locally, and turn
it into whichever form of BIG-IP configuration you need:

1. **Step-by-step GUI instructions** with every field value filled in
2. **tmsh commands**, numbered by step, as a runnable script
3. **An AS3 declaration** for automation

```bash
export F5XC_API_TOKEN=...
python3 xcbot.py fetch --tenant acme --namespace bot-defense \
                       --infra my-bot-infra
python3 xcbot.py build --vs secureapp
```

Python 3.7+ standard library only — no `requests`, so it also runs on a stock
BIG-IP.

---

## The two commands

**`fetch`** is the only step that talks to XC. It reads the Bot Infrastructure
and the Bot Endpoint Policy it references, normalizes them, and writes
`botdefense_inputs.json`.

**`build`** reads that file, asks what it cannot know — which virtual server —
and writes the artifacts. It needs no credentials and no network.

The split is the point: the same inputs file always produces the same config, so
you can commit it, diff it against last week's, and review it as the record of
what XC actually said.

```
  XC API ──fetch──▶ botdefense_inputs.json ──build──▶ out/<vs>_botdefense_ui.md
                     (commit this)                    out/<vs>_botdefense.sh
                                                      out/<vs>_botdefense_as3.json
                                                      out/<irule>.tcl
```

Pick a subset with `--ui`, `--tmsh`, `--as3`; the default is all of them.

### Interactive by default

Omit an answer and you get asked. `--namespace` and `--infra` become pick-lists
from the API; `--vs` becomes a pick-list of real virtual servers when you pass
`--bigip`, which also warns you if an object name is already taken:

```bash
python3 xcbot.py fetch --tenant acme
python3 xcbot.py build --bigip bigip.example.com --bigip-user admin
```

`--yes` turns every unanswered question into an error instead of a prompt, for
CI. So does a non-tty stdin.

---

## What gets generated, and why

XC Bot Defense in `REVERSE_PROXY` mode is a service the BIG-IP **steers traffic
into**. The BIG-IP does not evaluate bot policy itself. That splits into two
independent jobs, which is why there is both a policy and an iRule.

**Steering** — an LTM policy, `first-match`:

| # | Condition | Action |
|---|---|---|
| 0 | path contains a value in the JS data group | → bot pool |
| 1+ | method + `shape-header` absent + path *op* a value in an endpoint data group | → bot pool (fallback: app pool) |
| — | nothing matched | → the VS's own pool |

The `shape-header` condition is the loop guard. Bot Defense sets that header on
requests it has already inspected and is handing back; without the condition
those would be sent straight back into the bot pool.

**You do not specify the fallback pool.** It is the only thing the VS's own pool
name is needed for, and the VS already knows it, so the generated script reads
it off the VS when it runs:

```bash
FALLBACK=$(tmsh -c 'list ltm virtual secureapp pool' | sed -n 's/^[[:space:]]*pool //p')
```

and substitutes it into the policy before merging. If the VS has no pool, the
`fallback-pool` lines are dropped and the script says so. `--default-pool`
overrides this — worth using only when you are generating for a virtual server
that does not exist yet.

Traffic matching no rule reaches the application through the VS's own pool
regardless; the fallback pool only covers the narrower case where a rule *does*
match but the bot pool has no available member.

**Injection** — an HTML profile plus an iRule. The `<script>` goes into `<head>`,
but only on *entrypoints*: the endpoints XC marks `GET_DOCUMENT`. The iRule
calls `HTML::disable` on every response and re-enables it per request, so the
HTML parser never runs on API or asset traffic.

### Objects created

With the default `--prefix bot-defense`:

| Object | Name | Comes from |
|---|---|---|
| `ltm monitor https` | `bot-defense-hc` | the service's own `/sedcloudapi/health` |
| `ltm pool` | `bot-defense-pool` | infra `cloud_hosted.infra_host_name`, as an auto-populating FQDN member |
| `ltm data-group` | `bot-defense-js` | `js_download_path`, query stripped |
| `ltm data-group` | `bot-defense-entrypoint` | `GET_DOCUMENT` endpoints; value holds the methods |
| `ltm data-group` | `bot-defense-endpoints-<method>-<op>[-ci][-not]` | protected endpoint paths |
| `ltm html-rule` | `bot-defense-js-rule` | `js_download_path`, query kept |
| `ltm profile html` | `bot-defense-js-profile` | — |
| `ltm rule` | `bot-defense-irule` | — |
| `ltm policy` | `bot-defense-policy` | endpoint methods and match operators |

**Why one data group per method *and operator*.** An LTM policy rule ANDs its
conditions, and one condition carries exactly one operator and one case flag.
So endpoints are grouped by everything that has to match identically — method,
operator, case sensitivity, negation — and each group gets its own data group
and rule. They all forward to the same pool, which reproduces the policy's OR
across them. Editing a path later is a one-line `tmsh modify ltm data-group`
with no regeneration.

Endpoints that already agree collapse on their own: two GET endpoints both
using `ends-with` share one rule. A method splits only when XC asked for two
different operators on it — for instance a login endpoint carrying both
`equals /rest/user/login` and `contains /login` needs two POST rules, because
one condition cannot hold two operators and two conditions would be ANDed.

`--merge-ops OP` forces one data group and one rule per method by rewriting
every matcher to `OP`, case-insensitively. Fewer objects, but the config no
longer says what XC says:

- **`contains`** is the only `OP` that cannot *miss* a protected endpoint — it
  matches a superset of all four operators. Everything else can produce false
  negatives, and you get a warning naming each one.
- Even `contains` widens. Watch for an `ends-with /` document endpoint: as
  `contains /` it is true of every path, so **all** traffic for that method
  reaches the bot pool, static assets included. The tool detects exactly this
  and warns.

Left alone, the default reproduces XC faithfully. Reach for `--merge-ops` when
you would rather curate one list per method by hand than track what XC says.

### Case sensitivity

LTM policy string conditions are **case-insensitive by default** — `tmsh help
ltm policy` marks it with a `*`. So an XC matcher with `case_insensitive: true`
emits no keyword, and one with `case_insensitive: false` emits `case-sensitive`.
AS3 works the same way round (`caseSensitive` defaults to `false`). Data-group
records are lowercased only for the case-insensitive groups.

---

## Deploying

Nothing is ever sent to a BIG-IP by `fetch` or `build`. Three ways to apply the
result, in increasing order of automation:

```bash
# 1. by hand, from out/<vs>_botdefense_ui.md

# 2. run the script on the box
scp out/secureapp_botdefense.sh root@bigip:/var/tmp/
ssh root@bigip 'bash /var/tmp/secureapp_botdefense.sh'

# 3. push it
python3 xcbot.py deploy --bigip bigip.example.com --tmsh out/secureapp_botdefense.sh
python3 xcbot.py deploy --bigip bigip.example.com --as3  out/secureapp_botdefense_as3.json
```

`deploy` uploads and runs the artifact you already reviewed — it never
regenerates. It prompts before doing anything.

In the tmsh script, **steps 1–7 only create objects**; step 8 is the only one
that touches the virtual server, and step 8 reads the VS's current iRule list
and appends to it rather than replacing it. A rollback command list is in the
footer of every generated script.

### AS3 caveats

- Objects go into `/Common/Shared/`, which is where a `/Common` virtual server
  can reference them from.
- **The declaration does not attach anything to the VS.** A hand-built virtual
  server is not AS3-managed and AS3 will not modify objects it does not own.
  Attach with the three tmsh commands from step 8, or move the VS into AS3.
- AS3's forward action has no `fallback-pool`, so that one property from the
  tmsh artifact is not reproduced. It only matters when the bot pool is down.
- AS3 must be installed on the target (`/mgmt/shared/appsvcs/info`). `deploy`
  checks and tells you if it is not.

---

## Files

| File | Contents |
|---|---|
| `xcbot.py` | CLI, prompting, orchestration |
| `xc_api.py` | XC client and `normalize()` — the only place the XC schema is understood |
| `render.py` | `build_plan()` and the three renderers |
| `bigip_api.py` | BIG-IP discovery and deploy |
| `rest.py` | stdlib HTTP |
| `bna_vs_test_*.txt` | F5's stock AVK connector iRules, kept for reference — not used by this tool |

`build_plan()` makes every decision; the renderers only describe the plan. That
is what keeps the GUI steps, the tmsh script and the AS3 declaration from
drifting apart. Add a decision there, never in a renderer.

---

## Options worth knowing

| Option | |
|---|---|
| `--default-pool` | override the `fallback-pool`; normally read off the VS at run time |
| `--merge-ops` | one data group + rule per method, at the cost of fidelity (see above) |
| `--prefix` | prefix for every object name (default `bot-defense`) |
| `--shape-header` | the loop-guard header name (default `shape-header`) |
| `--inject-tag` | `head` or `body` |
| `--out-dir` | default `out/` |
| `--raw` | on `fetch`, also save the unmodified XC responses |
| `--token-file` | read the API token from a file instead of `F5XC_API_TOKEN` |
| `--policy` | on `fetch`, fail if the infra runs a different policy than expected |

`--infra` is what identifies everything else: the infra object names the policy
that cluster is actually running *and* advertises the host to send traffic to.
Fetching a policy without one would give you endpoints with nowhere to send them.

---

## Known behaviour

- **Mobile endpoints are skipped.** They use the Bot Defense SDK, not BIG-IP JS
  injection. The count is reported.
- **`path_and` and `path_none` endpoints are skipped**, with a named warning in
  every artifact. Neither has a single-rule LTM policy equivalent. `path_or` and
  `all_path` are handled.
- **An entrypoint of `/` matches everything.** The iRule tests entrypoints with
  `contains`, so a `/` record enables the HTML profile on all HTML responses.
  That is what an XC policy with an `ends-with /` document endpoint is asking
  for; narrow the data group if you want a tighter scope. You get a warning.
- **Paths are validated, not escaped.** Anything carrying a character that could
  break out of a tmsh value, a TCL string, a shell word or an HTML attribute is
  dropped and reported rather than escaped four different ways.
- **FQDN pool members need DNS** configured on the BIG-IP, and egress to the
  service on 443.
