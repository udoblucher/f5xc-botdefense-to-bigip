# Quick start

Step-by-step, from nothing to a protected virtual server. This is the "how";
[README.md](README.md) is the "why" — read it before you put this on production
traffic, especially [Coexisting with existing
iRules](README.md#coexisting-with-existing-irules).

---

## Minimum requirements

**On the machine you run `xcbot.py` on**

| | |
|---|---|
| Python | 3.7 or newer. Standard library only — nothing to `pip install`. |
| OS | Anything Python runs on. macOS, Linux, or the BIG-IP itself. |
| Network | Outbound HTTPS to `<tenant>.console.ves.volterra.io`, for `fetch` only. `build` needs no network at all. |
| Optional | Reachability of the BIG-IP management address, if you want `--bigip` discovery or `deploy`. |

**In F5 Distributed Cloud**

| | |
|---|---|
| Tenant | Your XC tenant name, the first label of your console URL. |
| API token | Administration ▸ Personal Management ▸ Credentials ▸ Add Credentials, type **API Token**. |
| Permissions | Read on the namespace's Bot Defense objects (`/api/shape/bot/...`) and on `/api/web/namespaces` for the namespace pick-list. Read-only is enough — this tool never writes to XC. |
| Objects | A **Bot Infrastructure** in `REVERSE_PROXY` mode, with a **Bot Endpoint Policy** attached. Any other mode still builds, but warns — the steering design assumes reverse proxy and is wrong for anything else. |

**On the BIG-IP**

| | |
|---|---|
| Modules | LTM provisioned. Nothing else — Bot Defense evaluation happens in XC, not here. |
| Access | `admin`/root for tmsh, or an Administrator-role account for REST. |
| Virtual server | The VS you are protecting must already exist and have an **HTTP profile** — the LTM policy matches on HTTP, and the HTML profile cannot attach without one. |
| DNS | A resolver must be configured: the generated bot pool member is the Bot Defense service **FQDN**, not an IP. |
| Egress | Outbound 443 from the BIG-IP to that service host. |
| Version | Verified on **17.5.1**. Everything generated (LTM policies, data groups, HTML profiles, OneConnect) is long-standing LTM, but 17.5.1 is the only version this has been run against. |
| For AS3 only | AS3 installed, 3.54.0 or newer. Skip if you use the GUI or tmsh output. |

---

## Step 1 — get the code

```bash
git clone https://github.com/udoblucher/f5xc-botdefense-to-bigip.git
cd f5xc-botdefense-to-bigip
python3 xcbot.py --help
```

No build, no install, no virtualenv.

## Step 2 — put your API token in place

Run `fetch` once with no token and it creates the file for you, mode `0600`,
explaining itself:

```bash
python3 xcbot.py fetch --tenant acme
```

Open `xc_api_token.txt`, replace the last line (`PASTE_YOUR_XC_API_TOKEN_HERE`)
with your token, and save. Keep the comment lines — they are what tells you
where the token came from when you return in six months.

The file is gitignored. `--token-file PATH` reads a different one, and
`F5XC_API_TOKEN` works for CI.

## Step 3 — fetch the policy from XC

```bash
python3 xcbot.py fetch --tenant acme
```

Omit `--namespace` and `--infra` and you get pick-lists built from the API.
To skip the prompts:

```bash
python3 xcbot.py fetch --tenant acme --namespace bot-defense --infra my-bot-infra
```

This writes **`botdefense_inputs.json`** — the normalized record of what XC
said. It is the only step that talks to XC. Read the warnings it prints:
skipped mobile endpoints, skipped `path_and`/`path_none` endpoints, and a
policy-version mismatch are all reported here.

> `botdefense_inputs.json` contains your tenant name, the Bot Defense service
> host and its egress IPs. It is gitignored on purpose. Commit it in a private
> repo if you want the audit trail; never in a public one.

## Step 4 — decide which pages get the telemetry script

XC does not record this, so it is yours to supply. One `--entrypoint` per page
that returns HTML needing the `<script>`:

```bash
--entrypoint /login --entrypoint /checkout
```

Omit it and the data group gets a single `/` record, which matches every path —
injection on every HTML response. That is the deliberate can't-miss default, and
you get a warning until you map the real pages. It is a data group, so you can
correct it later on the box without regenerating anything.

## Step 5 — build the artifacts

```bash
python3 xcbot.py build --vs secureapp --entrypoint /login
```

Into a partition instead of `/Common` — one flag, and the whole object set is
created inside it:

```bash
python3 xcbot.py build --partition prod --vs shop     # or just: --vs /prod/shop
```

Add `--bigip bigip.example.com --bigip-user admin` to turn `--vs` into a
pick-list of real virtual servers, pre-fill the fallback pool, and get warned
about name collisions and about existing iRules that would defeat the policy.
Set `BIGIP_PASS` or you will be prompted.

You get four files in `out/`:

| File | What it is |
|---|---|
| `<vs>_botdefense_ui.md` | click-by-click GUI steps, every field value filled in |
| `<vs>_botdefense.sh` | numbered tmsh commands, runnable as-is |
| `<vs>_botdefense_as3.json` | AS3 declaration |
| `<prefix>-irule.tcl` | the iRule body on its own |

`--ui`, `--tmsh`, `--as3` pick a subset.

## Step 6 — read the output before you apply it

Non-negotiable, and it takes two minutes:

- The banner at the top of the `.sh` lists the partition, the virtual server,
  the XC source policy and its version.
- Every `WARNING:` in the output. Skipped endpoints mean requests that will not
  be protected.
- **The step marked `attach to <vs>  <-- affects live traffic`.** It is the
  second-to-last step; everything before it only creates objects. Nothing else
  in the script touches the VS.

## Step 7 — apply it

Three ways, pick one:

```bash
# a) by hand in the GUI — follow out/secureapp_botdefense_ui.md
#    Set the Partition/Path selector first if you used --partition.

# b) run the script on the box
scp out/secureapp_botdefense.sh root@bigip:/var/tmp/
ssh root@bigip 'bash /var/tmp/secureapp_botdefense.sh'

# c) let the tool push it
python3 xcbot.py deploy --bigip bigip.example.com --tmsh out/secureapp_botdefense.sh
```

`deploy` uploads the file you just reviewed and runs it — it never regenerates.
It prompts first.

For AS3, read [AS3 caveats](README.md#as3-caveats) first. Two matter most:
with `--partition`, **AS3 takes ownership of that whole partition** and deletes
objects in it that are not in the declaration; and the declaration does not
attach anything to a hand-built virtual server — you still run the attach
commands.

## Step 8 — verify it is working

The generated iRule ships with logging on (`botdefense_debug 1`), so the box
tells you what it decided:

```bash
ssh root@bigip 'tail -f /var/log/ltm'
```

Request an entrypoint page and you should see:

```
Bot Defense Entrypoint -- Client: 10.1.1.10 URI: /login
Decorate Response -- Enabling HTML Content Profile. Path: /login
```

Anything else logs `is NOT an Entrypoint`. Then check:

1. **The script is actually in the HTML** — `curl -s https://app/login | grep -i script`.
2. **Protected endpoints do not hang.** A hang means the loop guard is not
   matching; see the Rule 1 note in
   [README](README.md#rule-1--the-loop-guard). First thing to check is a SNAT
   between Bot Defense and the VS.
3. **The bot pool is up** — `tmsh show ltm pool bot-defense-pool`. Down means
   DNS or egress 443, in that order.

Once you are satisfied, set `static::botdefense_debug 0` in the iRule and
reload it. Leaving it at 1 logs a line per request.

## Rolling back

Every generated script carries the full rollback list in its footer, in
dependency order. Order matters: the iRule calls `HTML::disable`, so it must
come off the virtual server **before** the HTML profile it depends on, or the
detach is refused.

```bash
tail -20 out/secureapp_botdefense.sh
```

Detaching from the VS is the part that stops the behaviour; deleting the
objects afterwards is housekeeping.

---

## If something goes wrong

| Symptom | Cause |
|---|---|
| `API Group could not be determined` from `fetch` | Wrong tenant name, or the token lacks Bot Defense read access. |
| `fetch` prompts for nothing and exits | `--yes` with a missing option. Drop `--yes` to be asked. |
| `build` warns that the deployment mode is not `REVERSE_PROXY` | It still writes the artifacts, but do not use them: the whole steering design assumes reverse proxy. Fix the infra in XC. |
| `01020036:3 ... was not found` running the script | A partition mismatch: the VS is not in `--partition`. Name it as `/partition/name`. |
| `01071912:3 HTML::disable ... requires an associated HTML profile` | You are detaching in the wrong order, or the VS never got the HTML profile. iRule off first. |
| Protected endpoints hang | The loop guard is not matching. See step 8. |
| Pool down | DNS resolver, then egress 443 to the service FQDN. |
| Script not in the HTML | The page is not an entrypoint (check `/var/log/ltm`), or the origin returned a compressed response — the HTML profile has nothing to parse in gzip. The tool does not handle compression; *this one was not reproduced in the lab*. |
| An existing iRule sets a pool | Stop. It silently overrides the policy for the requests it touches — use F5's validated Shape connector iRule instead. See [README](README.md#coexisting-with-existing-irules). |
