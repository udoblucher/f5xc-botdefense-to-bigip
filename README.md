# xcbot — F5 XC Bot Defense → BIG-IP configuration

Fetch a Bot Endpoint Policy from F5 Distributed Cloud, save it locally, and turn
it into whichever form of BIG-IP configuration you need:

1. **Step-by-step GUI instructions** with every field value filled in
2. **tmsh commands**, numbered by step, as a runnable script
3. **An AS3 declaration** for automation

```bash
python3 xcbot.py fetch --tenant acme          # creates xc_api_token.txt, then
                                              # asks you to paste your token in
python3 xcbot.py fetch --tenant acme --namespace bot-defense \
                       --infra my-bot-infra
python3 xcbot.py build --vs secureapp
```

Python 3.7+ standard library only — no `requests`, so it also runs on a stock
BIG-IP.

### The API token

`fetch` reads it from `xc_api_token.txt` in the working directory. Run `fetch`
with no token anywhere and it creates that file (mode `0600`) with a placeholder
and tells you what to do:

```
# F5 Distributed Cloud API token, read by xcbot.py fetch.
#
# Replace the last line of this file with your token. Get one in the XC console:
#   Administration >> Personal Management >> Credentials >> Add Credentials
#   Credential type: API Token
...
PASTE_YOUR_XC_API_TOKEN_HERE
```

Comment lines are kept, so the file explains itself when you come back to it in
six months. It is gitignored; `xc_api_token.txt.example` is the committed copy.

`--token-file PATH` reads a different file. `F5XC_API_TOKEN` still works and is
checked last, for CI. `build` needs no token at all.

---

## The two commands

**`fetch`** is the only step that talks to XC. It reads the Bot Infrastructure
and the Bot Endpoint Policy it references, normalizes them, and writes
`botdefense_inputs.json`.

**`build`** reads that file, asks what it cannot know — which virtual server, and
which pages get the injected script — and writes the artifacts. It needs no
credentials and no network.

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

**Steering** — an LTM policy with the `first-match` strategy, so the order *is*
the logic:

| # | Rule | Conditions | Action |
|---|---|---|---|
| 0 | `…-js` | path contains a value in the JS data group | → bot pool |
| 1 | `…-return` | `shape-header` exists **and** client address in the egress data group | *none* |
| 2+ | `…-endpoints-*` | method + path *op* a value in an endpoint data group | → bot pool (fallback: app pool) |
| — | | nothing matched | → the VS's own pool |

#### Rule 0 — serve the telemetry JS, always

First and with no other condition, so the script is served by the Bot Defense
service whatever else is true of the request. The service terminates that path
itself rather than proxying it to the origin, so it never comes back as return
traffic and cannot loop.

#### Rule 1 — the loop guard

In `REVERSE_PROXY` mode Bot Defense is not a sidecar returning a verdict; it
forwards the real request on to its configured origin, **which is this same
virtual server**. So the BIG-IP sees every protected request twice. Rule 1 is
what tells the two visits apart, and it must precede the endpoint rules — remove
it and each protected endpoint loops between the BIG-IP and Bot Defense forever.

What you want is *"steer to the bot pool unless the request comes from an egress
address **and** carries the header"* — a NAND. An LTM rule can only AND its
conditions, so the positive case is matched here and stopped instead.

Both halves matter. `shape-header` is just a header and any client can set one,
so a header-only guard means a crafted request skips Bot Defense entirely.
Requiring an egress address too closes that: forging the header is not enough,
you would also have to originate from Bot Defense's network. The addresses come
from the Bot Infrastructure object (`spec.cloud_hosted.egress[].ip_address`) and
land in an `ip`-type data group. If the infra advertises none, the tool falls
back to testing `shape-header` absence on each endpoint rule and warns that the
guard is weaker.

The rule carries **no action**, which is how "let it through to the application"
is expressed: under `first-match` it matches, evaluation ends, and the request
proceeds to the virtual server's own pool.

That is worth stating precisely, because an action-less rule could plausibly
mean "no match, keep evaluating" — which would drop return traffic into the
endpoint rules and loop. It does not. Verified on 17.5.1 with two rules that
both matched one request: the action-less rule won on ordinal, the second rule
never ran, and the request was still load-balanced, to the VS's own pool. An
empty action list means *make no forwarding decision*, leaving the virtual
server's normal routing intact.

Naming the pool explicitly would read better but is not worth the cost: left
out, the pool lives in exactly one place — the virtual server — so repointing
the VS carries the return path with it instead of leaving a stale reference that
quietly routes to the old origin.

#### Rules 2+ — the protected endpoints

One rule per endpoint data group, each forwarding to the bot pool with the app
pool as its `fallback-pool`. They carry no `shape-header` condition of their own —
rule 1 already handled return traffic, and testing the header here as well would
be the spoofable form of the same check. See
[Why one data group per method *and operator*](#objects-created) below for how
the groups are formed.

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
but only on *entrypoints*, which are listed in a data group. The iRule calls
`HTML::disable` on every response and re-enables it per request, so the HTML
parser never runs on traffic that does not need it.

#### Entrypoints are not fetched — they are yours to map

This is the one part of the config XC cannot supply. The policy records which
endpoints are **protected**; it does not record which pages have to **carry the
script**. Those are different things: the script belongs on the page holding the
form (or the JS) that later calls a protected endpoint, and that page is usually
not itself a protected endpoint. `GET_DOCUMENT` looks like the answer and is not
— it marks endpoints XC expects to serve an HTML document, which is a claim
about the endpoint, not an injection site.

So `build` asks:

```
JS injection scope
  The telemetry <script> belongs on the pages carrying a form (or
  JS) that fires a protected endpoint. XC does not record which
  pages those are, so it cannot be fetched -- either you have
  mapped them, or the script goes into every HTML response.

Have the entrypoint pages been mapped?
  1. No  -- inject across the whole application (data group gets '/')   (default)
  2. Yes -- type the entrypoint paths now
```

Answer **no** and `bot-defense-entrypoint` gets one record, `/`. The iRule
matches entrypoints with `contains` and every path contains `/`, so every HTML
response is decorated — the whole application, and the HTML parser armed on all
of it. Wide, but it cannot miss a page, which is the right way round for a
default. You get a warning in every artifact saying exactly that.

Answer **yes**, or pass `--entrypoint` once per page:

```bash
python3 xcbot.py build --vs secureapp --entrypoint /login --entrypoint /account/transfer
```

`--entrypoint-methods` sets the methods recorded against each (default `GET` —
injection happens on the document request). Paths are validated the same way XC
paths are, and anchored with a leading `/`.

**This data group is maintained by hand from then on.** Nothing regenerates it,
because nothing knows the answer. Add pages as you map them:

```bash
tmsh modify ltm data-group internal bot-defense-entrypoint records add { /login { data GET } }
tmsh modify ltm data-group internal bot-defense-entrypoint records delete { / }   # drop the catch-all
```

A specific record wins over the catch-all while both are present — with `/` and
`/login { data GET,POST }` in the group, `/login` resolves to `GET,POST`. So you
can add pages first and delete `/` last, without a gap in coverage. One
exception to the hand-editing: **AS3 owns the data group once you deploy the
declaration**, so a redeploy reverts records added with tmsh or the GUI. Keep
the list in the `--entrypoint` flags that generate the declaration instead.

### Objects created

With the default `--prefix bot-defense`:

| Object | Name | Comes from |
|---|---|---|
| `ltm monitor https` | `bot-defense-hc` | the service's own `/sedcloudapi/health` |
| `ltm pool` | `bot-defense-pool` | infra `cloud_hosted.infra_host_name`, as an auto-populating FQDN member |
| `ltm data-group` (`ip`) | `bot-defense-egress` | infra `cloud_hosted.egress[].ip_address` |
| `ltm data-group` | `bot-defense-js` | `js_download_path`, query stripped |
| `ltm data-group` | `bot-defense-entrypoint` | **you** — `--entrypoint`, or `/` for everything; value holds the methods |
| `ltm data-group` | `bot-defense-endpoints-<method>-<op>[-ci][-not]` | protected endpoint paths |
| `ltm html-rule` | `bot-defense-js-rule` | `js_download_path`, query kept |
| `ltm profile html` | `bot-defense-js-profile` | — |
| `ltm profile one-connect` | `bot-defense-oneconnect` | `--oneconnect-mask`, default `255.255.255.255` |
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

### Partitions

`--partition NAME` builds the whole set inside that partition. Nothing else
changes — the object names, the policy, the iRule and the walkthrough are the
same; only where they land differs.

```bash
python3 xcbot.py build --vs shop --partition prod
python3 xcbot.py build --vs /prod/shop          # same thing: the path sets it
```

**A partition gets its own copy of every object, rather than sharing one set out
of `/Common`.** That is deliberate. Two partitions usually serve two different
applications, and those can sit behind different XC namespaces, so their Bot
Defense policy, protected endpoints, egress IPs and infra host are all different.
Sharing would force them to agree. Duplicate `bot-defense-pool` objects in
`/prod` and `/dev` pointing at different infra is the normal case, not a mistake.
Each build only ever reads and writes its own partition: the collision check
ignores same-named objects elsewhere, and the same name in another partition is
never reported as a conflict.

Two things differ per artifact, because the three targets name objects
differently:

- **The tmsh script** names everything absolutely (`/prod/bot-defense-pool`). It
  has to: a bare name resolves in the *current* folder, which for a root shell is
  `/Common`, so `modify ltm virtual shop` on a VS in `/prod` fails with
  `01020036:3: The requested Virtual Server (/Common/shop) was not found`. The
  script also gains a **preflight step** that exits before creating anything if
  the partition does not exist or the VS is not in it — otherwise a typo leaves
  a half-applied config, with the objects built and the attach step failing.
- **The GUI walkthrough** keeps bare names and opens with a note to set the
  **Partition / Path** selector first. The GUI has no per-object partition field:
  objects land in whatever that selector is showing.

`--partition` and a `/partition/name` VS are checked against each other; naming
both differently is an error rather than a guess. With `--bigip`, the partition
of the virtual server you pick wins, since the pick-list spans every partition.

### Coexisting with existing iRules

> **If the target virtual server already has an iRule that conditionally selects
> a pool, this LTM policy approach is not recommended.** Use F5's currently
> validated Shape connector iRule instead: it steers in TCL, where it can be
> *ordered* against your existing logic rather than competing with it. The rest
> of this section is why, and what to do if you keep the policy anyway.

`build` checks for this when you pass `--bigip`: it reads the iRules attached to
the virtual server, scans each body for `pool`, `node`, `virtual`, `LB::reselect`
and `LB::detach`, and names any that match in a warning carried into every
artifact. Without `--bigip` it cannot look, so the generated GUI walkthrough and
tmsh script both open with a "check this first" note and the command to run.

**An iRule's `pool` command beats the LTM policy's forward action, and iRule
priority does not change that.** Verified on 17.5.1 with three pools — one on the
virtual server, one selected by a policy rule, one selected by an iRule — logging
the winner from `LB_SELECTED`:

| Request | Final pool |
|---|---|
| neither condition | the VS's pool |
| policy condition only | the policy's pool |
| iRule condition only | the iRule's pool |
| **both** | **the iRule's pool** |

```
iRule HTTP_REQUEST priority 100 + policy forward  ->  the iRule's pool
iRule HTTP_REQUEST priority 500 + policy forward  ->  the iRule's pool
iRule HTTP_REQUEST priority 999 + policy forward  ->  the iRule's pool
```

Even at priority 100 — running before the policy — the iRule wins. You cannot
reorder your way out of it.

So if the target virtual server already has an iRule that conditionally selects
a pool, then **for exactly those requests this entire steering policy is
bypassed**:

- Protected endpoints reach the application uninspected. No error, no log — the
  pool stays green and coverage is simply gone.
- Rule 0 breaks too, and worse: the telemetry JS gets served by the application
  pool, which has no such path, so the script 404s and never loads. Entrypoint
  protection goes with it, not just the endpoints the iRule touched.
- Rule 1 is unaffected in practice — return traffic wants the application, which
  is where the iRule was sending it anyway.

Three ways out, best first:

1. **Steer in an iRule instead of the policy** — F5's validated Shape connector.
   This is exactly why F5's own AVK connector selects its pool in an iRule at
   `HTTP_REQUEST priority 999` rather than using an LTM policy: two iRules can be
   ordered against each other, an iRule and a policy cannot. Nothing competes in
   the first place. This is the recommendation whenever a conditional pool
   selection is already in play.
2. **Guard the existing iRule** so it defers on Bot Defense's paths. Workable if
   you own that iRule and its conditions are narrow:

   ```tcl
   when HTTP_REQUEST {
       set p [string tolower [HTTP::path -normalized]]
       if { [class match $p contains bot-defense-js] } { return }
       # ... existing conditional pool logic ...
   }
   ```

   Note this only defers on the telemetry JS. Every path the policy's endpoint
   rules steer needs the same treatment, which is why option 1 scales better.
3. **Drop the conflicting logic** if the policy can express it.

The generated iRule sets **no** pool — only `HTML::enable`/`disable` and
`SSL::disable` — so it never fights an existing pool-selecting iRule in either
direction. Nothing here has to be reconciled *with* it; the conflict, if any, is
between your existing iRule and the LTM policy.

### OneConnect

A OneConnect profile is created with `source-mask 255.255.255.255` and attached
alongside the HTML profile. The stock `oneconnect` profile ships with
`source-mask any`, which lets *unrelated clients* share one serverside
connection — the origin then cannot tell them apart by source address. A `/32`
mask confines reuse to a single client address. Everything else inherits from
the parent. `--oneconnect-mask ""` skips the profile entirely.

Two interactions with the rest of this config are worth knowing, both benign:

- **Rule 1's source-IP test is unaffected.** OneConnect multiplexes the
  *serverside* only. The clientside connection is one per client and its source
  address is constant for the connection's life, so `tcp address` resolves the
  same way for every request on a keep-alive. Bot Defense's return traffic
  arrives on its own connections from egress addresses either way.
- **`SERVER_CONNECTED` stops firing per request, and that is correct here.**
  With OneConnect it fires only when a new serverside connection opens. The
  iRule uses that event solely for `SSL::disable` when the pool member is not on
  443, and SSL is negotiated once per connection. Nothing in the iRule keeps
  serverside state between requests, so there is nothing to leak across reuse.

Requests steered to the bot pool and requests falling through to the app pool
never share a serverside connection: OneConnect keys reuse to the pool member.

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

In the tmsh script, **only the second-to-last step touches the virtual server** —
everything before it just creates objects. That step is numbered for you in the
banner (`attach to <vs>  <-- affects live traffic`), and it reads the VS's
current iRule list and appends to it rather than replacing it. The last step
saves. A rollback command list is in the footer of every generated script, in
dependency order — the iRule has to come off the virtual server *before* the
HTML profile it calls `HTML::disable` on, or the detach is refused.

### AS3 caveats

- Objects go into `/<partition>/Shared/`, which is where a virtual server in that
  partition can reference them from. The AS3 tenant *is* the BIG-IP partition.
- **With `--partition`, AS3 takes ownership of the whole partition.** Posting the
  declaration makes AS3 authoritative for that tenant, and it removes objects in
  it that are not in the declaration — so a partition someone built by hand loses
  that config. `/Common` is exempt, which is why the default target is safe and a
  named partition is not. The declaration carries this warning in its own
  `remark`. Deploy the tmsh artifact instead unless the partition is already
  AS3-managed.
- **The embedded iRule names the entrypoint data group differently from the
  `.tcl` file**, and that is correct rather than drift: AS3 puts the data group in
  `/<partition>/Shared/` while tmsh puts it beside the virtual server, and
  `class match` does not search for it (see Known behaviour).
- **The declaration does not attach anything to the VS.** A hand-built virtual
  server is not AS3-managed and AS3 will not modify objects it does not own.
  Attach with the tmsh commands from the attach step, or move the VS into AS3.
- AS3's forward action has no `fallback-pool`, so that one property from the
  tmsh artifact is not reproduced. It only matters when the bot pool is down.
- The return-traffic rule is emitted with an empty `actions` array, which is
  the AS3 equivalent of the action-less tmsh rule. Do not "fix" it by adding
  a forward: pointing it at the bot pool recreates the loop it prevents.
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
| `xc_api_token.txt.example` | the placeholder token file, copied to `xc_api_token.txt` on first run |

`build_plan()` makes every decision; the renderers only describe the plan. That
is what keeps the GUI steps, the tmsh script and the AS3 declaration from
drifting apart. Add a decision there, never in a renderer.

---

## Options worth knowing

| Option | |
|---|---|
| `--entrypoint` | page whose HTML gets the `<script>`; repeat per page. Omitted → `/`, i.e. everything |
| `--entrypoint-methods` | methods recorded against each entrypoint (default `GET`) |
| `--default-pool` | override the `fallback-pool`; normally read off the VS at run time |
| `--merge-ops` | one data group + rule per method, at the cost of fidelity (see above) |
| `--oneconnect-mask` | OneConnect source mask (default `255.255.255.255`; `""` skips the profile) |
| `--prefix` | prefix for every object name (default `bot-defense`) |
| `--shape-header` | the loop-guard header name (default `shape-header`) |
| `--inject-tag` | `head` or `body` |
| `--inputs` | inputs file to build from (default `botdefense_inputs.json`) |
| `--out-dir` | default `out/` |
| `--partition` | partition to build the whole set in (default `Common`); implied by a `/partition/name` VS. See [Partitions](#partitions) |
| `--raw` | on `fetch`, also save the unmodified XC responses |
| `--token-file` | read the API token from a different file than `./xc_api_token.txt` |
| `--policy` | on `fetch`, fail if the infra runs a different policy than expected |
| `--verify-bigip-tls` | verify the BIG-IP certificate (off by default — it is self-signed) |

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
- **Entrypoints default to `/`, which means everything.** The iRule tests
  entrypoints with `contains`, so a `/` record enables the HTML profile on every
  HTML response. That is the deliberate fallback for "nobody has mapped the
  pages yet" — it cannot miss one. Verified on 17.5.1: with a `/` record,
  `class match -value -- /static/app.css contains <dg>` returns the record's
  value. You get a warning until you pass `--entrypoint`. See
  [Entrypoints are not mapped for you](#entrypoints-are-not-fetched--they-are-yours-to-map).
- **`class match` resolves a data group against the *virtual server's* folder,
  not the iRule's, and it does not search.** Measured on 17.5.1 with the rule and
  data group both in `/part/Shared` and the VS in `/part`: only the full
  `/part/Shared/<name>` resolves — a bare name and `/part/<name>` both raise a TCL
  error, which aborts the event and takes the request with it. This is why the
  iRule inside the AS3 declaration names the data group with its full
  `/<partition>/Shared/` path while the `.tcl` file and the tmsh script name it
  where they put it. The two are generated from the same source with one
  parameter; do not paste one into the other's deployment.
- **Endpoints XC disables are skipped**, reported by name — `metadata.disable`
  is honoured rather than silently generating a rule for a switched-off endpoint.
- **A `/` record under `contains` or `starts-with` disables the filter.** It is
  true of every path, so that method's traffic all reaches the bot pool, static
  assets included. Easy to produce with `--merge-ops`; detected and warned about.
- **Paths are validated, not escaped.** Anything carrying a character that could
  break out of a tmsh value, a TCL string, a shell word or an HTML attribute is
  dropped and reported rather than escaped four different ways.
- **FQDN pool members need DNS** configured on the BIG-IP, and egress to the
  service on 443.
- **Rule 1 assumes Bot Defense reaches the VS directly**, so the client address
  the BIG-IP sees really is an egress IP. A SNAT or proxy in between breaks the
  match and the loop returns. F5's own AVK connector makes the same assumption
  with its `DG-IPs` group. It is the first thing to check if protected endpoints
  start hanging.
- **The version the infra runs may not be the policy's latest.** The config is
  built from the policy's current content; a mismatch is warned about, naming
  both versions.
- **An existing iRule that sets a pool silently defeats the whole policy** for
  the requests it touches, and where one exists the policy approach is not the
  right tool — use F5's validated Shape connector iRule. Detected and named when
  you pass `--bigip`. See
  [Coexisting with existing iRules](#coexisting-with-existing-irules) — this is
  the one to check before rolling onto a virtual server someone else built.
