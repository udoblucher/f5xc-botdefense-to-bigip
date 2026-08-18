#!/usr/bin/env python3
"""test_tmsh.py -- the generated tmsh script's reuse contract, offline.

What is asserted here is the part of the artifact that is hard to eyeball: that
every object it creates is stamped with a marker, that nothing is created or
merged without first checking whether it is already there, and that the one
object whose marker is a hash of its own body produces the same hash twice.

The inputs are a synthetic tenant, not `botdefense_inputs.json`: that file holds
a real tenant name and real egress addresses and is deliberately untracked, so a
test that needed it could not run for anyone else.

    python3 test_tmsh.py
"""

from __future__ import annotations

import difflib
import json
import re
import subprocess
import sys
import tempfile

from render import (FALLBACK_TOKEN, FAST_VARS, build_plan, fingerprint,
                    fingerprints, names_for, render_as3, render_fast,
                    render_tmsh)

FAILURES = []


def check(label, got, want):
    if got != want:
        FAILURES.append(f"{label}\n     got: {got!r}\n    want: {want!r}")


INPUTS = {
    "fetched_at": "2026-01-01T00:00:00Z",
    "xc": {
        "tenant": "acme", "namespace": "shop", "infra": "my-bot-infra",
        "policy": "shop-bot-policy", "deployment_mode": "REVERSE_PROXY",
        "policy_version_deployed": 7, "policy_version_latest": 7,
    },
    "bot_service": {
        "host": "bot.example.net", "port": 443,
        "egress_ips": ["203.0.113.10", "203.0.113.11/32"],
        "health_check": {"path": "/sedcloudapi/health",
                         "host": "bot.example.net"},
    },
    "js": {"match_path": "/common.js", "script_src": "/common.js?single"},
    "endpoints": [
        {"name": "login", "methods": ["POST"],
         "matches": [{"op": "equals", "value": "/login", "nocase": True,
                      "negate": False}]},
        {"name": "search", "methods": ["GET"],
         "matches": [{"op": "ends-with", "value": "/search", "nocase": False,
                      "negate": False}]},
    ],
}


def plan_for(**kw):
    args = {"vs": "secureapp", "prefix": "bot-defense"}
    args.update(kw)
    return build_plan(INPUTS, **args)


PLAN = plan_for()
SCRIPT = render_tmsh(PLAN)
LINES = SCRIPT.splitlines()
N = names_for("bot-defense")
FPS = fingerprints(PLAN)

# ---------------------------------------------------------------------------
# Every create carries a marker, and no create runs unguarded
# ---------------------------------------------------------------------------
# The whole reuse contract rests on the marker being there: an object created
# without one is indistinguishable, on the next run, from one somebody built by
# hand -- so it would draw the "not created by this tool" note forever.
creates = [ln.strip() for ln in LINES if "tmsh -c 'create " in ln]
check("there are creates to check at all", len(creates) >= 6, True)
unstamped = [c for c in creates if "description xcbot:" not in c]
check("every single-line create stamps a marker", unstamped, [])

# The multi-line objects go in through a merge, so their marker is in the .conf
# heredoc instead. Both `description "xcbot:..."` (html-rule, policy) and the
# body comment (iRule, which has no description property) count.
#
# Counted on the invocation, not on the words: the mismatch report prints the
# same command as a hint, and a hint is not a write.
merges = [ln.strip() for ln in LINES
          if ln.strip().startswith("tmsh -c 'load sys config merge")]
check("three objects are merged, not created", len(merges), 3)
check("the iRule body carries its own fingerprint",
      bool(re.search(r"# xcbot-fingerprint: [0-9a-f]{12}", SCRIPT)), True)
check("both merged config objects carry a description marker",
      len(re.findall(r'description "xcbot:[0-9a-f]{12}"', SCRIPT)), 2)

# Guard-before-create, positionally: the read that decides has to come before
# the write it gates. A create that drifted above its own `if [ -z "$LIVE" ]`
# would still look right in a diff and would fail on every re-run.
for i, ln in enumerate(LINES):
    s = ln.strip()
    if not (s.startswith("tmsh -c 'create ")
            or s.startswith("tmsh -c 'load sys config merge")):
        continue
    window = LINES[max(0, i - 12):i]
    absent = [w for w in window if 'if [ -z "$LIVE" ]; then' in w]
    check(f"line {i + 1} is guarded by an existence check: {ln.strip()[:52]}",
          bool(absent), True)

# Nothing modifies or deletes an existing object. The one `tmsh -c "modify`
# permitted is the attach step, which adds to the virtual server's own lists.
for ln in LINES:
    s = ln.strip()
    if s.startswith("tmsh -c") and ("modify" in s or "delete" in s):
        check(f"the only modify is the attach: {s[:60]}",
              "modify ltm virtual" in s, True)

# ---------------------------------------------------------------------------
# The helper block is valid bash on every build
# ---------------------------------------------------------------------------
# `bash -n` is the only check that covers the helpers themselves -- they are a
# raw string in render.py that nothing else parses.
with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as fh:
    fh.write(SCRIPT)
    script_path = fh.name
r = subprocess.run(["bash", "-n", script_path], capture_output=True, text=True)
check(f"bash -n accepts the rendered script\n    {r.stderr.strip()}",
      r.returncode, 0)

# And with a partition, a merged operator and no OneConnect -- the paths that
# rewrite names and drop a whole step.
alt = render_tmsh(plan_for(partition="tenant1", merge_op="contains",
                           oneconnect_mask="", entrypoints=["/login"]))
with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as fh:
    fh.write(alt)
    alt_path = fh.name
r2 = subprocess.run(["bash", "-n", alt_path], capture_output=True, text=True)
check(f"bash -n accepts the partitioned variant\n    {r2.stderr.strip()}",
      r2.returncode, 0)

# ---------------------------------------------------------------------------
# Fingerprint stability -- the property the iRule check depends on
# ---------------------------------------------------------------------------
# build_irule stamps a timestamp into line 1, so two builds are never
# byte-identical and the fingerprint is the only thing that can say "same
# rule". If the timestamp leaked into the hash, every re-run would abort.
IRULE_FP = re.compile(r"# xcbot-fingerprint: ([0-9a-f]+)")
first = plan_for()
second = plan_for()
second["irule"]["text"] = second["irule"]["text"].replace(
    first["meta"]["generated"], "1999-12-31T23:59:59Z")
check("two builds agree on the iRule fingerprint",
      IRULE_FP.search(first["irule"]["text"]).group(1),
      IRULE_FP.search(second["irule"]["text"]).group(1))
check("...and the timestamp really did differ",
      first["irule"]["text"] == second["irule"]["text"], False)

# What the iRule *does* depend on is the two names in its body: the policy it
# names in its header comment and the entrypoint data group it reads. So an
# endpoint change leaves it alone -- endpoints live in the policy, and the
# policy's own marker is what notices them -- while a new prefix or partition
# moves the data-group path the rule resolves and must change the hash.
moved = INPUTS | {"endpoints": INPUTS["endpoints"] + [
    {"name": "checkout", "methods": ["PUT"],
     "matches": [{"op": "starts-with", "value": "/checkout", "nocase": False,
                  "negate": False}]}]}
changed = build_plan(moved, vs="secureapp", prefix="bot-defense")
check("a changed endpoint changes the policy fingerprint",
      fingerprints(changed)[N["policy"]] != FPS[N["policy"]], True)
check("a changed endpoint leaves the iRule fingerprint alone",
      IRULE_FP.search(changed["irule"]["text"]).group(1),
      IRULE_FP.search(first["irule"]["text"]).group(1))
check("a different prefix changes the iRule fingerprint",
      IRULE_FP.search(plan_for(prefix="other")["irule"]["text"]).group(1)
      != IRULE_FP.search(first["irule"]["text"]).group(1), True)
check("a different partition changes the iRule fingerprint",
      IRULE_FP.search(plan_for(partition="tenant1")["irule"]["text"]).group(1)
      != IRULE_FP.search(first["irule"]["text"]).group(1), True)

# ---------------------------------------------------------------------------
# fingerprints() is what both readers read
# ---------------------------------------------------------------------------
# render_tmsh and xcbot's collision check take their markers from this one
# table. If a value in it stopped matching what the script emits, the check
# would confidently report "this build's own object" about somebody else's.
stamped = set(re.findall(r"xcbot:([0-9a-f]{12})", SCRIPT))
stamped.update(IRULE_FP.findall(SCRIPT))
check("every marker in the script comes from the table",
      sorted(stamped - set(FPS.values())), [])
check("every object in the table is stamped in the script",
      sorted(set(FPS.values()) - stamped), [])
check("the table covers one entry per object",
      len(FPS), 6 + 1 + len(PLAN["datagroups"]))   # +1: OneConnect
check("the monitor's marker hashes what the script compares",
      FPS[N["monitor"]],
      fingerprint(str(PLAN["monitor"]["interval"]),
                  str(PLAN["monitor"]["timeout"]), PLAN["monitor"]["send"]))

# Dropping OneConnect drops its entry rather than leaving a stale one.
check("no OneConnect entry when there is no OneConnect profile",
      names_for("bot-defense")["oneconnect"]
      in fingerprints(plan_for(oneconnect_mask="")), False)

# The default path leaves the fallback pool out of the marker entirely: it is
# hashed with the placeholder still in it, because the real pool is read off the
# virtual server when the script runs and no build-time hash could include it.
# The live fallback-pool is compared separately, against WANTFB.
check("the placeholder is what the marker is hashed with",
      FALLBACK_TOKEN in render_tmsh(plan_for()), True)
check("the script compares the resolved fallback pool on its own",
      "WANTFB" in SCRIPT and "fallback-pools" in SCRIPT, True)
# Named explicitly, though, the pool is part of the policy and belongs in the
# marker -- two policies steering their overflow to different pools are not the
# same policy.
check("a named fallback pool is part of the policy marker",
      fingerprints(plan_for(default_pool="pool_a"))[N["policy"]]
      != fingerprints(plan_for(default_pool="pool_b"))[N["policy"]], True)

# ---------------------------------------------------------------------------
# The reports the operator reads
# ---------------------------------------------------------------------------
check("the header says it is safe to re-run", "SAFE TO RE-RUN" in SCRIPT, True)
check("a mismatch is counted, not just printed",
      "XCB_REUSED" in SCRIPT and "XCB_CREATED" in SCRIPT, True)
check("the run ends with a created/reused summary",
      "Created $XCB_CREATED object(s), reused $XCB_REUSED." in SCRIPT, True)
check("a kept .conf survives the temp-dir cleanup",
      "KEEP=/var/tmp" in SCRIPT, True)
check("the hand-maintained data group is never diffed",
      "exists -- hand-maintained, left alone" in SCRIPT, True)
check("record differences point at sync rather than being applied",
      "sync --check" in SCRIPT, True)

# ---------------------------------------------------------------------------
# The loop-guard header is a parameter, not a constant
# ---------------------------------------------------------------------------
# It is the service's name to choose, so a deployment that sends something else
# has to be buildable. The check that matters is that the value reaches the
# rendered policy: the default being right for most tenants is exactly what
# would hide a renderer that hardcoded it.
custom = render_tmsh(plan_for(shape_header="x-my-bot-header"))
check("a custom header name reaches the policy condition",
      "name x-my-bot-header" in custom, True)
check("...and the default is nowhere in that build",
      "shape-header" in custom, False)
check("the default is still the default",
      "name shape-header" in SCRIPT, True)
# Written unquoted into `name <hdr>`, so a space would parse as another tmsh
# keyword and an empty value would drop the condition's name -- neither shows
# up until `load sys config merge` runs, on a box.
for bad in ("", "   ", "x-my header", "x-my-header:", "x-my-header\nfoo"):
    try:
        plan_for(shape_header=bad)
    except ValueError:
        pass
    else:
        FAILURES.append(f"header name {bad!r} was accepted\n"
                        f"     got: no error\n    want: ValueError")


# ---------------------------------------------------------------------------
# The FAST template renders back to the AS3 declaration
# ---------------------------------------------------------------------------
# render_fast() does not build its own objects -- it runs render_as3() over a
# plan whose parameterised values are sentinels. This is the test that keeps
# that true: substitute the template's own default values back into its own
# template body and the result has to be the AS3 artifact, byte for byte,
# except where the difference is deliberate. Add an object to render_as3 and
# it appears in both; parameterise something without a default and this fails.
FAST = render_fast(PLAN)

_head, _sep, _tmpl = FAST.partition("template: |\n")
check("the template has a block scalar to read", bool(_sep), True)

# Defaults come out of the emitted YAML, not out of _fast_default() -- the
# point is that the file is self-consistent, not that one function agrees with
# itself.
_defaults = {k: json.loads(v) for k, v in re.findall(
    r"^  (\w+):$(?:\n    .*)*?\n    default: (.*)$", _head, re.M)}
check("every variable has a default in definitions",
      sorted(_defaults), sorted(n for n, *_ in FAST_VARS))

_body = "\n".join(ln[2:] if ln.startswith("  ") else ln
                  for ln in _tmpl.splitlines())
for _name, _kind, *_rest in FAST_VARS:
    _v = _defaults[_name]
    if _kind == "integer":
        # Unquoted in the template, so the rendered JSON gets a number.
        check(f"{_name} is annotated ::integer",
              "{{%s::integer}}" % _name in _body, True)
        _body = _body.replace("{{%s::integer}}" % _name, str(int(_v)))
    else:
        _body = _body.replace("{{%s}}" % _name, json.dumps(_v)[1:-1])

check("no mustache tag is left unaccounted for",
      re.findall(r"\{\{.*?\}\}", _body), [])

_got = json.loads(_body)                       # also asserts it is valid JSON
_want = json.loads(render_as3(PLAN))["declaration"]

# The one deliberate difference. `purpose` becomes an AS3 remark truncated to
# 64 characters; naming the header there would both go stale the moment
# somebody changes the field and risk a {{tag}} being cut in half, which would
# render as nothing. So the FAST variant describes the header instead.
_dg = N["dg_egress"]
_tenant = "Common"
check("the egress remark names the header in AS3",
      "shape-header" in _want[_tenant]["Shared"][_dg]["remark"], True)
check("...and describes it instead in FAST",
      "loop-guard" in _got[_tenant]["Shared"][_dg]["remark"], True)
_got[_tenant]["Shared"][_dg]["remark"] = _want[_tenant]["Shared"][_dg]["remark"]

# Compared as a diff, not as two dicts: these are ~200-line declarations and
# check() prints both sides, so an equality failure here would bury the one
# line that changed under everything that did not.
_diff = [ln for ln in difflib.unified_diff(
    json.dumps(_want, indent=2, sort_keys=True).splitlines(),
    json.dumps(_got, indent=2, sort_keys=True).splitlines(),
    "as3", "fast", lineterm="", n=0) if not ln.startswith("@@")]
check("the rendered template IS the AS3 declaration",
      [ln[:110] for ln in _diff[2:12]], [])

# The iRule names the entrypoint data group by full path, and the path carries
# the tenant -- so the body differs per rendering and the fingerprint comment
# inside it can only be right for one of them. It has to be right for the
# default rendering, or a FAST deployment and a tmsh deployment of identical
# TCL would carry different provenance markers.
check("the iRule keeps the tenant parameterised",
      "/{{tenant_name}}/Shared/" in _tmpl, True)

check("the template says which lists are not fields",
      "WHAT IS A FIELD AND WHAT IS NOT" in _head, True)
check("the template carries the XC policy version it came from",
      f"v{PLAN['meta']['version']}" in _head, True)

# A custom header has to reach the FAST defaults too, or the form pre-fills the
# wrong name and the guard rule silently never matches.
check("a custom --shape-header reaches the template default",
      '"x-my-bot-header"' in render_fast(plan_for(shape_header="x-my-bot-header")),
      True)

# A field the template body never uses is worse than a missing one: somebody
# sets it and wonders why the box did not change. Dropping the OneConnect
# profile has to drop its field with it.
_no_oc = render_fast(plan_for(oneconnect_mask=""))
check("no OneConnect profile means no OneConnect field",
      "oneconnect_mask" in _no_oc, False)
check("...and the rest of the form survives it",
      "shape_header" in _no_oc and "tenant_name" in _no_oc, True)

# ---------------------------------------------------------------------------
if FAILURES:
    print(f"{len(FAILURES)} FAILED\n")
    for f in FAILURES:
        print(f"  - {f}\n")
    sys.exit(1)
print("all tmsh tests passed")
