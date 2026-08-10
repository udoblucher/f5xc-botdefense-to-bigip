#!/usr/bin/env python3
"""render.py -- inputs file + answers -> a plan -> the three output formats.

    build_plan()   inputs + answers  ->  plan   (every decision made here)
    render_ui()    plan -> Configuration-utility walkthrough (Markdown)
    render_tmsh()  plan -> numbered tmsh commands (runnable bash)
    render_as3()   plan -> AS3 declaration (JSON)

The plan is the single source of truth: all three renderers describe the same
objects, so the GUI steps, the tmsh script and the AS3 declaration can never
drift apart. Add a decision to build_plan, never to a renderer.

THE DESIGN BEING GENERATED
--------------------------
XC Bot Defense in REVERSE_PROXY mode is a service the BIG-IP steers traffic
into; the BIG-IP does not evaluate bot policy itself. Two independent jobs:

  Steering (LTM policy, first-match -- the order IS the logic)
      rule 0  path contains <js data-group>                  -> bot pool
      rule 1  shape-header exists AND source in <egress dg>  -> no action
      rule 2+ method + path <op> <dg>                        -> bot pool,
                                                               fallback app pool
      no match                                               -> VS default pool

    Rule 0 first and unconditional: the telemetry script is always served by the
    Bot Defense service. That path is terminated by the service rather than
    proxied to the origin, so it never comes back as return traffic.

    Rule 1 is the loop guard, and it only has to precede the endpoint rules.
    "Steer to the bot pool unless the request is from an egress address AND
    carries the header" is a NAND, and an LTM rule can only AND its conditions,
    so the positive case is matched here and stopped. Carrying no action,
    first-match ends evaluation and the request proceeds to the VS's own pool.

    Both halves of rule 1 matter. The shape-header alone is a value any client
    can set, so a header-only guard lets a crafted request skip Bot Defense
    entirely; pairing it with the service's egress addresses closes that. When
    the infra advertises no egress addresses we fall back to testing the header
    on each endpoint rule instead, and say so.

  Injection (HTML profile + iRule)
      The telemetry <script> is injected into the <head> of responses, but only
      on entrypoints -- the pages XC marks GET_DOCUMENT. The iRule disables the
      HTML profile by default and re-enables it per response, so the parser
      never runs on traffic that does not need it.

Object names, paths and methods all come from XC. Only the virtual server, its
default pool and the name prefix come from the operator.
"""

from __future__ import annotations

import datetime
import json

# Operator names are shared verbatim by tmsh and AS3 -- only negation differs,
# because AS3 folds it into the operator instead of using a `not` keyword.
_OP_AS3_NEG = {"equals": "does-not-equal", "starts-with": "does-not-start-with",
               "ends-with": "does-not-end-with", "contains": "does-not-contain"}
_OP_ORDER = {"equals": 0, "starts-with": 1, "ends-with": 2, "contains": 3}

# Placeholder for "the pool already attached to the virtual server". The tmsh
# script substitutes it on the box, where that answer is authoritative and free
# to obtain -- so nobody has to retype a pool name the VS already knows.
FALLBACK_TOKEN = "__XCBOT_VS_POOL__"


def names_for(prefix: str) -> dict:
    """Every object name derived from one prefix.

    Distinct names per object type on purpose. The hand-built config on the
    reference box reuses `bot-defense` for the pool, the policy and the iRule,
    which is legal in tmsh but collides in AS3 (object names are JSON property
    names there) and is hard to read in logs either way.
    """
    p = prefix.rstrip("-")
    return {
        "pool":         f"{p}-pool",
        "monitor":      f"{p}-hc",
        "policy":       f"{p}-policy",
        "irule":        f"{p}-irule",
        "html_rule":    f"{p}-js-rule",
        "html_profile": f"{p}-js-profile",
        "oneconnect":   f"{p}-oneconnect",
        "dg_js":        f"{p}-js",
        "dg_entry":     f"{p}-entrypoint",
        "dg_egress":    f"{p}-egress",
        "dg_ep_prefix": f"{p}-endpoints",
    }


# ---------------------------------------------------------------------------
# Plan
# ---------------------------------------------------------------------------
# Merging every matcher onto one operator only avoids letting a protected
# endpoint slip past if the merged operator matches a superset of what the
# original did. `contains` is a superset of all four; the others are not.
_MERGE_SAFE = "contains"


def _endpoint_buckets(inputs: dict, dg_prefix: str,
                      merge_op: str = "") -> tuple[list[dict], list[str]]:
    """Protected endpoints -> one data-group + one LTM policy rule per bucket.

    An LTM policy rule ANDs its conditions and a single condition holds exactly
    one operator and one case flag, so endpoints are grouped by everything that
    has to match identically: (method, operator, case sensitivity, negation).
    Every bucket forwards to the same pool, which reproduces the policy's OR
    across them. Endpoints that already agree on all four collapse into one
    bucket on their own -- two GET endpoints both using ends-with need only one
    rule between them.

    `merge_op` forces one data group and one rule per method by rewriting every
    matcher to that operator, case-insensitively. Fewer objects, at the cost of
    no longer matching what XC specified; the widening (and any narrowing) is
    reported. Negated matchers are never merged -- folding a `not` in with the
    others would inverted-match the whole group.
    """
    buckets: dict[tuple, list[str]] = {}
    sources: dict[tuple, list[str]] = {}
    warnings: list[str] = []
    widened: list[str] = []
    narrowed: list[str] = []

    for ep in inputs.get("endpoints", []):
        methods = ep.get("methods") or ["ANY"]
        for method in methods:
            for m in ep.get("matches", []):
                op, nocase = m["op"], bool(m["nocase"])
                if merge_op and not m["negate"]:
                    if op != merge_op:
                        change = widened if merge_op == _MERGE_SAFE else narrowed
                        change.append(f"{ep.get('name') or '(unnamed)'}: "
                                      f"{op} {m['value']} -> {merge_op}")
                    op, nocase = merge_op, True
                value = m["value"].lower() if nocase else m["value"]
                key = (method, op, nocase, bool(m["negate"]))
                if value not in buckets.setdefault(key, []):
                    buckets[key].append(value)
                    sources.setdefault(key, []).append(
                        f"{ep.get('name') or '(unnamed)'}: {m['op']} {m['value']}")

    if widened:
        warnings.append(
            f"--merge-ops {merge_op} rewrote {len(widened)} matcher(s), which "
            f"steers MORE traffic to Bot Defense than the XC policy asks for "
            f"(no protected endpoint is missed): " + "; ".join(widened))
    if narrowed:
        warnings.append(
            f"--merge-ops {merge_op} rewrote {len(narrowed)} matcher(s) to an "
            f"operator that is not a superset of the original, so a protected "
            f"endpoint CAN now be missed. Use --merge-ops {_MERGE_SAFE} to "
            f"merge without that risk: " + "; ".join(narrowed))

    out = []
    for key in sorted(buckets, key=lambda k: (k[0], _OP_ORDER.get(k[1], 9), k[2], k[3])):
        method, op, nocase, negate = key
        if merge_op and not negate:
            name = f"{dg_prefix}-{method.lower()}"
        else:
            parts = [dg_prefix, method.lower(), op.replace("-", "")]
            if nocase:
                parts.append("ci")
            if negate:
                parts.append("not")
            name = "-".join(parts)
        out.append({
            "dg": name,
            "method": method,
            "op": op,
            "nocase": nocase,
            "negate": negate,
            "values": sorted(buckets[key]),
            "sources": sources[key],
        })
    return out, warnings


def _entrypoint_records(inputs: dict) -> list[tuple[str, str]]:
    """(path, methods) records for the JS-injection data-group.

    Keys are lowercased because the iRule lowercases the request path before
    matching. The value holds the methods, which the iRule tests with a
    substring check -- that is why they are comma-joined rather than a list.
    """
    recs: dict[str, set] = {}
    for ep in inputs.get("endpoints", []):
        if not ep.get("entrypoint"):
            continue
        for m in ep.get("matches", []):
            recs.setdefault(m["value"].lower(), set()).update(ep.get("methods") or ["GET"])
    return [(k, ",".join(sorted(v))) for k, v in sorted(recs.items())]


def build_irule(plan: dict) -> str:
    """The injection-scoping iRule. Behaviour matches the validated reference
    rule; the data-group name and the log switch are the only parameters."""
    n = plan["names"]
    return f"""# Generated by xcbot.py -- {plan['meta']['generated']}
# Source: XC {plan['meta']['namespace']}/{plan['meta']['policy']} v{plan['meta']['version']}
#
# This rule does NOT steer traffic -- the LTM policy {n['policy']} does that.
# Its job is to keep the HTML parser off every response that does not need it:
# the HTML profile is disabled by default and enabled only for responses to a
# request whose path is an XC entrypoint (a GET_DOCUMENT endpoint).
when RULE_INIT {{
    # 1 = log every request decision to /var/log/ltm, 0 = silent.
    # Leave at 1 while validating, then set to 0 and reload the rule.
    set static::botdefense_debug 1
    # Entrypoint paths + their methods. Change the data-group to change the
    # injection scope -- no need to touch this rule.
    set static::botdefense_entrypoints "{n['dg_entry']}"
}}

when HTTP_REQUEST priority 500 {{
    set xc_decorate 0
    set xc_path [string tolower [HTTP::path -normalized]]
    set xc_method [HTTP::method]

    if {{ [class match -value -- $xc_path contains $static::botdefense_entrypoints] contains $xc_method }} {{
        set xc_decorate 1
        if {{ $static::botdefense_debug }} {{
            log local0. "Bot Defense Entrypoint -- Client: [IP::client_addr] URI: [HTTP::uri]"
        }}
    }} else {{
        if {{ $static::botdefense_debug }} {{
            log local0. "Request: $xc_method [HTTP::uri] is NOT an Entrypoint"
        }}
    }}
}}

when SERVER_CONNECTED priority 500 {{
    # SSL offload: the app pool may be cleartext even though the bot pool is 443.
    if {{ [LB::server port] != 443 }} {{
        SSL::disable
    }}
}}

when HTTP_RESPONSE priority 500 {{
    HTML::disable
    if {{ $xc_decorate }} {{
        if {{ $static::botdefense_debug }} {{
            log local0. "Decorate Response -- Enabling HTML Content Profile. Path: $xc_path"
        }}
        HTML::enable
    }}
}}"""


def build_plan(inputs: dict, *, vs: str, default_pool: str = "",
               prefix: str = "bot-defense", shape_header: str = "shape-header",
               partition: str = "Common", inject_tag: str = "head",
               merge_op: str = "",
               oneconnect_mask: str = "255.255.255.255") -> dict:
    """Every decision that turns XC data + operator answers into objects.

    `default_pool` is optional and feeds exactly one property: the per-rule
    `fallback-pool`, which is what a matched request falls back to when the bot
    pool has no available member. Traffic that matches no rule already reaches
    the application through the virtual server's own pool, so the name is never
    needed for that.

    Left empty, the tmsh script reads the pool off the virtual server when it
    runs, so the fallback is right without anyone naming it. Pass it only to
    override that, or when generating for a VS that does not exist yet.
    """
    n = names_for(prefix)
    xc = inputs["xc"]
    svc = inputs["bot_service"]
    js = inputs["js"]
    hc = svc.get("health_check") or {}

    buckets, warnings = _endpoint_buckets(inputs, n["dg_ep_prefix"], merge_op)
    entry = _entrypoint_records(inputs)

    # Bot Defense's egress addresses, from the infra object. These are what make
    # the return-traffic rule trustworthy: the shape-header alone is a value any
    # client can set, so a header-only test is a bypass waiting to happen.
    egress = [ip if "/" in ip else f"{ip}/32"
              for ip in (svc.get("egress_ips") or [])]

    datagroups = []
    if egress:
        datagroups.append({
            "name": n["dg_egress"],
            "type": "ip",
            "purpose": "Bot Defense egress addresses. Combined with the "
                       f"{shape_header} header, these identify traffic Bot "
                       "Defense has already inspected and is handing back.",
            "records": [(ip, "") for ip in egress],
        })
    datagroups.append({
        "name": n["dg_js"],
        "purpose": "Path of the Bot Defense telemetry JavaScript. Requests for "
                   "it are served by the Bot Defense service, not the app.",
        "records": [(js["match_path"], "")],
    })
    if entry:
        datagroups.append({
            "name": n["dg_entry"],
            "purpose": "Entrypoints: paths whose HTML response gets the <script> "
                       "injected. Key = path (lowercase), value = methods.",
            "records": entry,
        })
    for b in buckets:
        datagroups.append({
            "name": b["dg"],
            "purpose": f"Protected endpoints matched with "
                       f"{'NOT ' if b['negate'] else ''}{b['op']}"
                       f"{' (case-insensitive)' if b['nocase'] else ''} "
                       f"for {b['method']} requests.",
            "records": [(v, "") for v in b["values"]],
            "sources": b["sources"],
        })

    # Order is the logic here -- the strategy is first-match.
    #
    #   0  JS path                -> bot pool, unconditionally
    #   1  return traffic         -> no action, falls through to the app
    #   2+ protected endpoints    -> bot pool, fallback to the app pool
    #
    # The JS rule is FIRST so the telemetry script is always served by the Bot
    # Defense service, whatever else is true of the request. Bot Defense
    # terminates that path itself rather than proxying it to the origin, so it
    # never arrives as return traffic and cannot loop.
    rules = [{
        "name": n["dg_js"],
        "why": "Serve the telemetry JS from the Bot Defense service. First, and "
               "with no other condition, so it is served regardless.",
        # Case-insensitive on purpose: the JS path is generated by XC and the
        # browser echoes it verbatim, but a case-folding proxy in between
        # should not be able to knock the telemetry request off its route.
        "conditions": [{"kind": "path", "op": "contains", "dg": n["dg_js"],
                        "nocase": True, "negate": False}],
        "pool": n["pool"],
        "fallback": "",
    }]
    if egress:
        # Must come BEFORE the endpoint rules. "Steer to the bot pool unless the
        # request is from an egress address AND carries the header" is a NAND,
        # and an LTM rule can only AND its conditions -- so the positive case is
        # matched here and stopped. Carrying no action, first-match ends
        # evaluation and the request proceeds to the VS's own pool: no pool name
        # needed, and no way back into the bot pool.
        rules.append({
            "name": f"{prefix.rstrip('-')}-return",
            "why": f"Traffic Bot Defense already inspected and handed back "
                   f"-- it carries {shape_header} AND comes from an address in "
                   f"{n['dg_egress']}. Both halves are needed: the header alone "
                   f"is something any client could set.",
            "conditions": [
                {"kind": "header-exists", "name": shape_header},
                {"kind": "src-ip", "dg": n["dg_egress"], "negate": False},
            ],
            "pool": "",
            "fallback": "",
        })
    for b in buckets:
        conds = []
        if b["method"] != "ANY":
            conds.append({"kind": "method", "values": [b["method"]]})
        if not egress:
            # No egress list to check, so the header is all there is to go on.
            # Weaker: a client that sets the header itself skips Bot Defense.
            conds.append({"kind": "header-absent", "name": shape_header})
        conds.append({"kind": "path", "op": b["op"], "dg": b["dg"],
                      "nocase": b["nocase"], "negate": b["negate"]})
        rules.append({
            "name": b["dg"],
            "why": f"{b['method']} requests to the protected paths in {b['dg']}.",
            "conditions": conds,
            "pool": n["pool"],
            "fallback": default_pool or FALLBACK_TOKEN,
        })
    # A record of "/" under contains or starts-with is true of every path, so
    # the rule stops being a filter at all. Easy to produce by merging an
    # `ends-with /` document endpoint onto another operator.
    for b in buckets:
        if b["op"] in ("contains", "starts-with") and "/" in b["values"]:
            warnings.append(
                f"Data group {b['dg']} contains the record '/' matched with "
                f"{b['op']}, which is true of every path: ALL {b['method']} "
                f"traffic now goes to the bot pool, static assets included. "
                f"Drop that record, or match it with ends-with instead.")
    if not egress:
        warnings.append(
            f"The infra advertises no egress addresses, so return traffic is "
            f"recognised by the {shape_header} header alone. That header is a "
            f"value any client can set, so a crafted request carrying it will "
            f"skip Bot Defense. Check the Bot Infrastructure in XC and re-run "
            f"fetch to pick the addresses up.")
    if not entry:
        warnings.append(
            "The policy has no GET_DOCUMENT endpoint, so no entrypoint was "
            "derived and the <script> would never be injected. Add an "
            "entrypoint in XC, or pass --entrypoint PATH.")
    for path, _ in entry:
        if path == "/":
            warnings.append(
                "Entrypoint '/' is matched with `contains`, so every path "
                "contains it and the HTML profile is enabled on all HTML "
                "responses. That is what the XC policy asks for; narrow the "
                f"{n['dg_entry']} data-group if you want a tighter scope.")
    for u in inputs.get("unsupported_endpoints", []):
        warnings.append(f"Endpoint '{u['name']}' not generated -- {u['reason']}")
    if inputs.get("mobile_endpoint_count"):
        warnings.append(
            f"{inputs['mobile_endpoint_count']} mobile endpoint(s) skipped -- "
            f"mobile uses the Bot Defense SDK, not BIG-IP JS injection.")
    if xc.get("deployment_mode") and xc["deployment_mode"] != "REVERSE_PROXY":
        warnings.append(
            f"Infra deployment_mode is {xc['deployment_mode']}, not "
            f"REVERSE_PROXY. This steering design assumes reverse proxy.")
    if xc.get("policy_version_deployed") != xc.get("policy_version_latest"):
        warnings.append(
            f"XC policy latest version is {xc['policy_version_latest']} but "
            f"infra '{xc['infra']}' runs {xc['policy_version_deployed']}. This "
            f"config was built from the policy's current content; if the two "
            f"versions differ in endpoints, redeploy the policy in XC first.")

    plan = {
        "meta": {
            "generated": datetime.datetime.now(datetime.timezone.utc)
                                 .strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tenant": xc["tenant"], "namespace": xc["namespace"],
            "infra": xc["infra"], "policy": xc["policy"],
            "version": xc["policy_version_deployed"],
            "fetched_at": inputs.get("fetched_at", ""),
        },
        "vs": vs,
        "default_pool": default_pool,
        # True when the fallback pool is left to the script to read off the VS.
        "fallback_from_vs": not default_pool,
        "partition": partition,
        "shape_header": shape_header,
        "names": n,
        "monitor": {
            "name": n["monitor"], "interval": 5, "timeout": 16,
            "send": f"GET {hc.get('path', '/sedcloudapi/health')} HTTP/1.1\\r\\n"
                    f"host: {hc.get('host', '')}\\r\\nconnection: close\\r\\n",
            "recv": "",
        },
        "pool": {"name": n["pool"], "host": svc["host"], "port": svc["port"],
                 "monitor": n["monitor"], "alternates": svc.get("regional_hosts", [])},
        "datagroups": datagroups,
        "html_rule": {"name": n["html_rule"], "tag": inject_tag,
                      "content": f"<script src=\"{js['script_src']}\"></script>"},
        "html_profile": {"name": n["html_profile"], "rule": n["html_rule"],
                         "content_selection": ["text/html", "text/xhtml"]},
        # Serverside connection reuse, restricted to one client address. The
        # stock profile's `source-mask any` lets unrelated clients share a
        # serverside connection, which hides the real source from the origin;
        # a /32 mask keeps reuse within a single client.
        "oneconnect": ({"name": n["oneconnect"], "source_mask": oneconnect_mask}
                       if oneconnect_mask else None),
        "irule": {"name": n["irule"], "text": ""},
        "policy": {"name": n["policy"], "strategy": "first-match", "rules": rules},
        "egress_ips": svc.get("egress_ips", []),
        "warnings": warnings,
    }
    plan["irule"]["text"] = build_irule(plan)
    return plan


# ---------------------------------------------------------------------------
# Renderer 1 -- Configuration utility (GUI) walkthrough
# ---------------------------------------------------------------------------
def _cond_english(c: dict) -> str:
    if c["kind"] == "method":
        return f"HTTP Method **is** `{'`, `'.join(c['values'])}`"
    if c["kind"] == "header-absent":
        return f"HTTP Header `{c['name']}` **does not exist**"
    if c["kind"] == "header-exists":
        return f"HTTP Header `{c['name']}` **exists**"
    if c["kind"] == "src-ip":
        neg = "does not match" if c.get("negate") else "matches"
        return (f"TCP *Address* (client) **{neg}** any address in data group "
                f"`{c['dg']}`")
    neg = "does not " if c["negate"] else ""
    ci = " (case-insensitive)" if c["nocase"] else ""
    return f"HTTP URI *path* {neg}**{c['op']}** any value in data group `{c['dg']}`{ci}"


def render_ui(plan: dict) -> str:
    m, n = plan["meta"], plan["names"]
    L = []
    A = L.append
    A(f"# BIG-IP setup for F5 XC Bot Defense — virtual server `{plan['vs']}`")
    A("")
    A(f"Generated {m['generated']} by `xcbot.py` from XC data fetched {m['fetched_at']}.")
    A("")
    A("| | |")
    A("|---|---|")
    A(f"| XC tenant | `{m['tenant']}` |")
    A(f"| Namespace | `{m['namespace']}` |")
    A(f"| Bot Infrastructure | `{m['infra']}` |")
    A(f"| Bot Endpoint Policy | `{m['policy']}` v{m['version']} |")
    A(f"| Bot Defense service | `{plan['pool']['host']}:{plan['pool']['port']}` |")
    A(f"| Target virtual server | `{plan['vs']}` (partition `{plan['partition']}`) |")
    A("| Fallback pool | " + (f"`{plan['default_pool']}`"
                              if plan["default_pool"]
                              else f"whichever pool is on `{plan['vs']}`") + " |")
    A("")
    if plan["warnings"]:
        A("> **Read first**")
        for w in plan["warnings"]:
            A(f"> - {w}")
        A("")
    A("All navigation below is from the BIG-IP Configuration utility. Steps 1–7 "
      "create objects and change nothing about live traffic; **step 8 is the "
      "only step that affects the virtual server**.")
    A("")

    step = 1
    A(f"## Step {step} — Health monitor")
    A("")
    A("**Local Traffic ›› Monitors ›› Create**")
    A("")
    A("| Field | Value |")
    A("|---|---|")
    A(f"| Name | `{plan['monitor']['name']}` |")
    A("| Type | `HTTPS` |")
    A("| Parent Monitor | `https` |")
    A(f"| Interval | `{plan['monitor']['interval']}` |")
    A(f"| Timeout | `{plan['monitor']['timeout']}` |")
    A(f"| Send String | `{plan['monitor']['send']}` |")
    A("| Receive String | *(leave empty)* |")
    A("")
    A("The send string targets the Bot Defense service's own health endpoint, "
      "so the pool only comes up when the service is actually answering.")
    A("")

    step += 1
    A(f"## Step {step} — Pool for the Bot Defense service")
    A("")
    A("**Local Traffic ›› Pools ›› Pool List ›› Create**")
    A("")
    A("| Field | Value |")
    A("|---|---|")
    A(f"| Name | `{plan['pool']['name']}` |")
    A(f"| Health Monitors | `{plan['monitor']['name']}` |")
    A("| New Members | select **Node List → FQDN** |")
    A(f"| ‣ FQDN | `{plan['pool']['host']}` |")
    A(f"| ‣ Service Port | `{plan['pool']['port']}` |")
    A("| ‣ Auto Populate | `Enabled` |")
    A("")
    A("An FQDN member needs a working DNS resolver under **System ›› "
      "Configuration ›› Device ›› DNS**; without one the member never resolves.")
    if plan["pool"]["alternates"]:
        A("")
        A(f"Regional alternates advertised by XC (use only if you must pin a "
          f"region): {', '.join('`' + h + '`' for h in plan['pool']['alternates'])}.")
    A("")

    step += 1
    A(f"## Step {step} — Data groups")
    A("")
    A("**Local Traffic ›› iRules ›› Data Group List ›› Create** — one per table, "
      "all of type **String**.")
    A("")
    for dg in plan["datagroups"]:
        A(f"### `{dg['name']}`")
        A("")
        A(dg["purpose"])
        A("")
        A("| String | Value |")
        A("|---|---|")
        for k, v in dg["records"]:
            A(f"| `{k}` | {'`' + v + '`' if v else '*(empty)*'} |")
        if dg.get("sources"):
            A("")
            A("<sub>From XC endpoints: " + "; ".join(dg["sources"]) + "</sub>")
        A("")

    step += 1
    A(f"## Step {step} — HTML rule (the injected tag)")
    A("")
    A("**Local Traffic ›› Profiles ›› Content ›› HTML Rules ›› Create**")
    A("")
    A("| Field | Value |")
    A("|---|---|")
    A("| Rule Type | `Append HTML` |")
    A(f"| Name | `{plan['html_rule']['name']}` |")
    A(f"| Match Tag Name | `{plan['html_rule']['tag']}` |")
    A(f"| Action / HTML Content | `{plan['html_rule']['content']}` |")
    A("")

    step += 1
    A(f"## Step {step} — HTML profile")
    A("")
    A("**Local Traffic ›› Profiles ›› Content ›› HTML ›› Create**")
    A("")
    A("| Field | Value |")
    A("|---|---|")
    A(f"| Name | `{plan['html_profile']['name']}` |")
    A("| Parent Profile | `html` |")
    A(f"| Content Selection | `{'`, `'.join(plan['html_profile']['content_selection'])}` |")
    A(f"| Available Rules → Selected | `{plan['html_profile']['rule']}` |")
    A("")

    if plan["oneconnect"]:
        step += 1
        oc = plan["oneconnect"]
        A(f"## Step {step} — OneConnect profile")
        A("")
        A("**Local Traffic ›› Profiles ›› Other ›› OneConnect ›› Create**")
        A("")
        A("| Field | Value |")
        A("|---|---|")
        A(f"| Name | `{oc['name']}` |")
        A("| Parent Profile | `oneconnect` |")
        A(f"| Source Mask | `{oc['source_mask']}` |")
        A("")
        A("The stock profile uses `source-mask any`, which lets unrelated "
          "clients share one serverside connection — the origin then cannot "
          "tell them apart by source address. A `/32` mask confines reuse to a "
          "single client. Everything else is left at the parent's defaults.")
        A("")

    step += 1
    A(f"## Step {step} — iRule")
    A("")
    A("**Local Traffic ›› iRules ›› iRule List ›› Create**")
    A("")
    A(f"Name: `{plan['irule']['name']}` — paste the body from "
      f"`{plan['irule']['name']}.tcl` (written next to this file).")
    A("")
    A("It disables the HTML profile on every response and re-enables it only "
      "for entrypoints, so the HTML parser never touches API or asset traffic.")
    A("")

    step += 1
    A(f"## Step {step} — Local Traffic Policy (the steering)")
    A("")
    A("**Local Traffic ›› Policies ›› Policy List ›› Create**")
    A("")
    A("| Field | Value |")
    A("|---|---|")
    A(f"| Name | `{plan['policy']['name']}` |")
    A(f"| Strategy | `{plan['policy']['strategy']}` |")
    A("| Requires | `http` |")
    A("| Controls | `forwarding` |")
    A("")
    A("Then add these rules **in this order** — the strategy is first-match, so "
      "order is the logic:")
    A("")
    for i, r in enumerate(plan["policy"]["rules"]):
        A(f"**Rule {i} — `{r['name']}`** — {r['why']}")
        A("")
        A("- Conditions (all must match):")
        for c in r["conditions"]:
            A(f"    - {_cond_english(c)}")
        if not r["pool"]:
            A("- Action: **none** — leave the Actions list empty. Under "
              "first-match the rule still matches and stops evaluation, so the "
              f"request goes to `{plan['vs']}`'s own pool.")
            A("")
            continue
        fb = ""
        if r["fallback"] == FALLBACK_TOKEN:
            fb = (f", *Fallback Pool* the pool already on `{plan['vs']}` "
                  f"(its **Properties** tab shows it)")
        elif r["fallback"]:
            fb = f", *Fallback Pool* `{r['fallback']}`"
        A(f"- Action: *Forward traffic to* **Pool** `{r['pool']}`{fb}")
        A("")
    A("Save the policy, then click **Publish** — a draft policy cannot be "
      "attached to a virtual server.")
    A("")
    A(f"The `{plan['shape_header']}` condition is what prevents a loop: Bot "
      f"Defense sets that header on requests it has already inspected and is "
      f"handing back, and those must reach the application, not the bot pool "
      f"again.")
    A("")

    step += 1
    A(f"## Step {step} — Attach to `{plan['vs']}` (the only traffic-affecting step)")
    A("")
    A(f"**Local Traffic ›› Virtual Servers ›› Virtual Server List ›› "
      f"{plan['vs']}**")
    A("")
    nth = 1
    A(f"{nth}. **Properties** tab, set the view to **Advanced**: set **HTML "
      f"Profile** to `{plan['html_profile']['name']}`. Update.")
    if plan["oneconnect"]:
        nth += 1
        A(f"{nth}. **Properties** tab (Advanced): set **OneConnect Profile** to "
          f"`{plan['oneconnect']['name']}`. Update.")
    nth += 1
    A(f"{nth}. **Resources** tab: under **Policies**, click **Manage…** and move "
      f"`{plan['policy']['name']}` into *Enabled*.")
    nth += 1
    A(f"{nth}. **Resources** tab: under **iRules**, click **Manage…** and move "
      f"`{plan['irule']['name']}` into *Enabled*. Order matters only if you have "
      f"other iRules touching `HTML::` or the response.")
    A("")

    step += 1
    A(f"## Step {step} — Verify")
    A("")
    A(f"1. **Local Traffic ›› Pools ›› {plan['pool']['name']}** shows *Available* "
      f"(green). If not, DNS resolution or egress to "
      f"`{plan['pool']['host']}:{plan['pool']['port']}` is the first thing to check.")
    A(f"2. Request an entrypoint path and confirm the `<script>` appears in the "
      f"HTML. With the iRule's debug flag at 1, `/var/log/ltm` logs one line per "
      f"request saying whether it was treated as an entrypoint.")
    A(f"3. **Statistics ›› Module Statistics ›› Local Traffic ›› Policies** "
      f"shows per-rule hit counts for `{plan['policy']['name']}`.")
    A("4. Once the traffic looks right, set `static::botdefense_debug` to `0` in "
      "the iRule — it logs on every request.")
    A("")
    if plan["egress_ips"]:
        A("### Origin allowlist")
        A("")
        A("Bot Defense sends the inspected traffic back from these addresses. If "
          "anything in front of the application filters by source IP, allow them:")
        A("")
        A("```")
        for ip in plan["egress_ips"]:
            A(ip)
        A("```")
        A("")
    return "\n".join(L)


# ---------------------------------------------------------------------------
# Renderer 2 -- tmsh
# ---------------------------------------------------------------------------
def _tmsh_str(s: str) -> str:
    """Escape a value for a double-quoted tmsh string.

    '?' matters: tmsh treats it as a glob character, which is why the reference
    box stores the injected tag as  src=\\"/common.js\\?single\\".
    """
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("?", "\\?")


def _tmsh_records(records: list[tuple[str, str]]) -> str:
    out = []
    for k, v in records:
        out.append(f"{k} {{ data {v} }}" if v else f"{k} {{ }}")
    return " ".join(out)


def _tmsh_conditions(rule: dict, indent: str) -> list[str]:
    lines = []
    for i, c in enumerate(rule["conditions"]):
        lines.append(f"{indent}{i} {{")
        if c["kind"] == "method":
            lines.append(f"{indent}    http-method")
            lines.append(f"{indent}    values {{ {' '.join(c['values'])} }}")
        elif c["kind"] in ("header-absent", "header-exists"):
            lines.append(f"{indent}    http-header")
            lines.append(f"{indent}    name {c['name']}")
            if c["kind"] == "header-absent":
                lines.append(f"{indent}    not")
            lines.append(f"{indent}    exists")
        elif c["kind"] == "src-ip":
            # Client address. The event is left at the default: tmsh normalizes
            # anything else to client-accepted here, and the address is the same
            # value at every event anyway.
            lines.append(f"{indent}    tcp")
            lines.append(f"{indent}    address")
            if c.get("negate"):
                lines.append(f"{indent}    not")
            lines.append(f"{indent}    matches")
            lines.append(f"{indent}    datagroup {c['dg']}")
        else:
            lines.append(f"{indent}    http-uri")
            lines.append(f"{indent}    path")
            lines.append(f"{indent}    {c['op']}")
            # LTM policy string conditions are case-INsensitive by default
            # (`tmsh help ltm policy` marks case-insensitive with *), so the
            # keyword that has to be written is the case-sensitive one.
            if not c["nocase"]:
                lines.append(f"{indent}    case-sensitive")
            if c["negate"]:
                lines.append(f"{indent}    not")
            lines.append(f"{indent}    datagroup {c['dg']}")
        lines.append(f"{indent}}}")
    return lines


def _policy_block(plan: dict) -> str:
    p = plan["policy"]
    # A tcp condition makes the policy require the tcp module as well as http.
    needs_tcp = any(c["kind"] == "src-ip"
                    for r in p["rules"] for c in r["conditions"])
    L = [f"ltm policy {p['name']} {{",
         "    controls { forwarding }",
         "    requires { http tcp }" if needs_tcp else "    requires { http }",
         f"    strategy {p['strategy']}",
         "    rules {"]
    for ordinal, r in enumerate(p["rules"]):
        L.append(f"        {r['name']} {{")
        L.append(f"            ordinal {ordinal}")
        L.append("            conditions {")
        L += _tmsh_conditions(r, "                ")
        L.append("            }")
        # No pool means no action: under first-match the rule still matches and
        # stops evaluation, so the request falls through to the VS's own pool.
        if r["pool"]:
            L.append("            actions {")
            L.append("                0 {")
            L.append("                    forward")
            L.append("                    select")
            if r["fallback"]:
                L.append(f"                    fallback-pool {r['fallback']}")
            L.append(f"                    pool {r['pool']}")
            L.append("                }")
            L.append("            }")
        L.append("        }")
    L += ["    }", "}"]
    return "\n".join(L)


def render_tmsh(plan: dict) -> str:
    m, n = plan["meta"], plan["names"]
    L = []
    A = L.append
    A("#!/bin/bash")
    A("#" + "=" * 74)
    A("#  BIG-IP configuration for F5 XC Bot Defense")
    A(f"#  Virtual server : {plan['vs']}   (fallback pool: "
      + (plan["default_pool"] if plan["default_pool"]
         else "read off the VS at run time") + ")")
    A(f"#  XC source      : {m['namespace']}/{m['policy']} v{m['version']} "
      f"via infra {m['infra']}")
    A(f"#  Generated      : {m['generated']} by xcbot.py")
    A("#" + "=" * 74)
    A("#")
    A("#  Run on the BIG-IP as root:   bash " + f"{plan['vs']}_botdefense.sh")
    A("#  Or copy the text inside each  tmsh -c '...'  into an interactive tmsh")
    A("#  shell, one step at a time.")
    A("#")
    A("#  Steps 1-7 only create objects -- live traffic is untouched until")
    A("#  STEP 8 attaches them to the virtual server.")
    if plan["warnings"]:
        A("#")
        A("#  NOTE:")
        for w in plan["warnings"]:
            A(f"#    - {w}")
    A("#" + "=" * 74)
    A("")
    A("set -e")
    A('TMP=$(mktemp -d /var/tmp/xcbot.XXXXXX)')
    A('trap "rm -rf $TMP" EXIT')
    A("")

    step, total = 1, 10 if plan["oneconnect"] else 9

    A(f'echo "== STEP {step}/{total} -- health monitor {plan["monitor"]["name"]} =="')
    mon = plan["monitor"]
    A(f"tmsh -c 'create ltm monitor https {mon['name']} defaults-from https "
      f"interval {mon['interval']} timeout {mon['timeout']} recv none "
      f"send \"{mon['send']}\"'")
    A("")

    step += 1
    A(f'echo "== STEP {step}/{total} -- pool {plan["pool"]["name"]} =="')
    pool = plan["pool"]
    A(f"tmsh -c 'create ltm pool {pool['name']} monitor {pool['monitor']} "
      f"members add {{ {pool['host']}:{pool['port']} {{ fqdn {{ autopopulate "
      f"enabled name {pool['host']} }} }} }}'")
    A("")

    step += 1
    A(f'echo "== STEP {step}/{total} -- data groups =="')
    A("# Edit these later with:")
    A(f"#   tmsh modify ltm data-group internal {n['dg_js']} records add {{ /path {{ }} }}")
    for dg in plan["datagroups"]:
        A(f"#  {dg['name']}: {dg['purpose']}")
        A(f"tmsh -c 'create ltm data-group internal {dg['name']} "
          f"type {dg.get('type', 'string')} "
          f"records add {{ {_tmsh_records(dg['records'])} }}'")
    A("")

    step += 1
    A(f'echo "== STEP {step}/{total} -- HTML rule (the injected script tag) =="')
    hr = plan["html_rule"]
    A("# Merged from a file rather than created inline: tmsh -c strips the")
    A("# escaped double quotes out of the tag, leaving src=/path unquoted.")
    A("cat > $TMP/htmlrule.conf <<'XCBOT_EOF'")
    A(f"ltm html-rule tag-append-html {hr['name']} {{")
    A("    action {")
    A(f"        text \"{_tmsh_str(hr['content'])}\"")
    A("    }")
    A("    match {")
    A(f"        tag-name {hr['tag']}")
    A("    }")
    A("}")
    A("XCBOT_EOF")
    A("tmsh -c 'load sys config merge file '$TMP'/htmlrule.conf'")
    A("")

    step += 1
    A(f'echo "== STEP {step}/{total} -- HTML profile =="')
    hp = plan["html_profile"]
    A(f"tmsh -c 'create ltm profile html {hp['name']} defaults-from html "
      f"content-selection add {{ {' '.join(hp['content_selection'])} }} "
      f"rules add {{ {hp['rule']} }}'")
    A("")

    if plan["oneconnect"]:
        step += 1
        oc = plan["oneconnect"]
        A(f'echo "== STEP {step}/{total} -- OneConnect profile {oc["name"]} =="')
        A("# Serverside connection reuse. The stock profile's `source-mask any`")
        A("# lets unrelated clients share a serverside connection; a /32 mask")
        A("# keeps reuse within one client address.")
        A(f"tmsh -c 'create ltm profile one-connect {oc['name']} "
          f"defaults-from oneconnect source-mask {oc['source_mask']}'")
        A("")

    step += 1
    A(f'echo "== STEP {step}/{total} -- iRule {plan["irule"]["name"]} =="')
    A("# Multi-line TCL has no single-line create form, so it is merged from a")
    A("# file. The same file is written next to this script as "
      f"{plan['irule']['name']}.tcl for the GUI path.")
    A(f"cat > $TMP/irule.conf <<'XCBOT_EOF'")
    A(f"ltm rule {plan['irule']['name']} {{")
    A(plan["irule"]["text"])
    A("}")
    A("XCBOT_EOF")
    A("tmsh -c 'load sys config merge file '$TMP'/irule.conf'")
    A("")

    step += 1
    A(f'echo "== STEP {step}/{total} -- LTM policy {plan["policy"]["name"]} =="')
    A("# Nested policy rules are merged for the same reason as the iRule.")
    A("# Merged policies are created published, so no separate publish is needed.")
    A("cat > $TMP/policy.conf <<'XCBOT_EOF'")
    A(_policy_block(plan))
    A("XCBOT_EOF")
    if plan["fallback_from_vs"]:
        A("")
        A("# fallback-pool = the pool already attached to the VS. Read here")
        A("# rather than asked for at build time: the VS is the authority on")
        A("# its own pool, and this is where that answer is free to get.")
        A(f"FALLBACK=$(tmsh -c 'list ltm virtual {plan['vs']} pool' "
          f"| sed -n 's/^[[:space:]]*pool //p')")
        A("if [ -n \"$FALLBACK\" ]; then")
        A(f'  echo "  fallback-pool: $FALLBACK  (read from {plan["vs"]})"')
        A(f"  sed -i \"s|{FALLBACK_TOKEN}|$FALLBACK|g\" $TMP/policy.conf")
        A("else")
        A(f'  echo "  {plan["vs"]} has no pool, so the rules get no'
          f' fallback-pool:"')
        A('  echo "  a matched request will fail if the bot pool is down."')
        A(f"  sed -i '/{FALLBACK_TOKEN}/d' $TMP/policy.conf")
        A("fi")
    A("tmsh -c 'load sys config merge file '$TMP'/policy.conf'")
    A("")

    step += 1
    A(f'echo "== STEP {step}/{total} -- attach to {plan["vs"]}  <-- affects live traffic =="')
    A("# 'rules' is an ordered list and REPLACES what is there, so read the")
    A("# current list first and append to it rather than overwriting.")
    A(f"EXISTING=$(tmsh -c 'list ltm virtual {plan['vs']} rules one-line' "
      f"| sed -n 's/.*rules {{\\([^}}]*\\)}}.*/\\1/p')")
    A(f'echo "  existing iRules on {plan["vs"]}: ${{EXISTING:-<none>}}"')
    profiles = [plan["html_profile"]["name"]]
    if plan["oneconnect"]:
        profiles.append(plan["oneconnect"]["name"])
    A(f"tmsh -c 'modify ltm virtual {plan['vs']} profiles add "
      f"{{ {' '.join(profiles)} }}'")
    A(f"tmsh -c 'modify ltm virtual {plan['vs']} policies add "
      f"{{ {plan['policy']['name']} }}'")
    A(f'case " $EXISTING " in')
    A(f'  *" {plan["irule"]["name"]} "*)')
    A(f'    echo "  {plan["irule"]["name"]} is already attached, leaving rules alone" ;;')
    A(f'  *)')
    A(f"    tmsh -c \"modify ltm virtual {plan['vs']} rules "
      f"{{ $EXISTING {plan['irule']['name']} }}\" ;;")
    A(f'esac')
    A("")

    step += 1
    A(f'echo "== STEP {step}/{total} -- save =="')
    A("tmsh -c 'save sys config'")
    A("")
    A(f'echo "Done. Check:  tmsh show ltm pool {plan["pool"]["name"]}"')
    A(f'echo "              tmsh show ltm policy {plan["policy"]["name"]}"')
    A(f'echo "              tail -f /var/log/ltm"')
    A("")
    A("#" + "-" * 74)
    A("# Roll back everything this script created:")
    A(f"#   tmsh modify ltm virtual {plan['vs']} profiles delete "
      f"{{ {plan['html_profile']['name']} }}")
    A(f"#   tmsh modify ltm virtual {plan['vs']} policies delete "
      f"{{ {plan['policy']['name']} }}")
    A(f"#   tmsh modify ltm virtual {plan['vs']} rules {{ }}   # then re-add yours")
    A(f"#   tmsh delete ltm policy {plan['policy']['name']}")
    A(f"#   tmsh delete ltm rule {plan['irule']['name']}")
    A(f"#   tmsh delete ltm profile html {plan['html_profile']['name']}")
    if plan["oneconnect"]:
        A(f"#   tmsh delete ltm profile one-connect {plan['oneconnect']['name']}")
    A(f"#   tmsh delete ltm html-rule tag-append-html {plan['html_rule']['name']}")
    for dg in plan["datagroups"]:
        A(f"#   tmsh delete ltm data-group internal {dg['name']}")
    A(f"#   tmsh delete ltm pool {plan['pool']['name']}")
    A(f"#   tmsh delete ltm monitor https {plan['monitor']['name']}")
    A("#" + "-" * 74)
    return "\n".join(L)


# ---------------------------------------------------------------------------
# Renderer 3 -- AS3
# ---------------------------------------------------------------------------
AS3_SCHEMA_VERSION = "3.54.0"


def _as3_conditions(rule: dict) -> list[dict]:
    out = []
    for c in rule["conditions"]:
        if c["kind"] == "method":
            out.append({"type": "httpMethod", "event": "request",
                        "all": {"operand": "equals", "values": c["values"]}})
        elif c["kind"] in ("header-absent", "header-exists"):
            op = "does-not-exist" if c["kind"] == "header-absent" else "exists"
            out.append({"type": "httpHeader", "event": "request",
                        "name": c["name"], "all": {"operand": op}})
        elif c["kind"] == "src-ip":
            out.append({"type": "tcp", "event": "request",
                        "address": {
                            "operand": "does-not-match" if c.get("negate")
                                       else "matches",
                            "datagroup": {"use": c["dg"]}}})
        else:
            op = _OP_AS3_NEG[c["op"]] if c["negate"] else c["op"]
            out.append({"type": "httpUri", "event": "request",
                        "path": {"operand": op,
                                 "datagroup": {"use": c["dg"]},
                                 # AS3 defaults caseSensitive to false, i.e.
                                 # case-insensitive -- the opposite of tmsh.
                                 "caseSensitive": not c["nocase"]}})
    return out


def render_as3(plan: dict) -> str:
    m, n = plan["meta"], plan["names"]
    app: dict = {"class": "Application", "template": "shared"}

    app[n["monitor"]] = {
        "class": "Monitor", "monitorType": "https",
        "interval": plan["monitor"]["interval"],
        "timeout": plan["monitor"]["timeout"],
        # AS3 takes the literal escapes; unlike tmsh it does not want '?' escaped.
        "send": plan["monitor"]["send"].replace("\\r\\n", "\\r\\n"),
        "receive": "",
    }
    app[n["pool"]] = {
        "class": "Pool",
        "monitors": [{"use": n["monitor"]}],
        "members": [{
            "servicePort": plan["pool"]["port"],
            "addressDiscovery": "fqdn",
            "hostname": plan["pool"]["host"],
            "autoPopulate": True,
        }],
    }
    for dg in plan["datagroups"]:
        app[dg["name"]] = {
            "class": "Data_Group", "storageType": "internal",
            "keyDataType": dg.get("type", "string"),
            "remark": dg["purpose"][:64],
            "records": [{"key": k, "value": v} for k, v in dg["records"]],
        }
    app[n["html_rule"]] = {
        "class": "HTML_Rule", "ruleType": "tag-append-html",
        "match": {"tagName": plan["html_rule"]["tag"]},
        "content": plan["html_rule"]["content"],
    }
    app[n["html_profile"]] = {
        "class": "HTML_Profile",
        "contentSelection": plan["html_profile"]["content_selection"],
        "rules": [{"use": n["html_rule"]}],
    }
    if plan["oneconnect"]:
        app[n["oneconnect"]] = {
            "class": "Multiplex_Profile",
            "sourceMask": plan["oneconnect"]["source_mask"],
        }
    app[n["irule"]] = {
        "class": "iRule", "expand": False, "iRule": plan["irule"]["text"],
    }
    app[n["policy"]] = {
        "class": "Endpoint_Policy",
        "strategy": plan["policy"]["strategy"],
        # An empty actions list is deliberate for the return-traffic rule: it
        # must match and stop evaluation WITHOUT forwarding, or it would send
        # Bot Defense's own return traffic straight back into the bot pool.
        "rules": [{
            "name": r["name"],
            "conditions": _as3_conditions(r),
            "actions": ([{"type": "forward", "event": "request",
                          "select": {"pool": {"use": r["pool"]}}}]
                        if r["pool"] else []),
        } for r in plan["policy"]["rules"]],
    }

    notes = [
        f"Generated by xcbot.py {m['generated']} from XC "
        f"{m['namespace']}/{m['policy']} v{m['version']} (infra {m['infra']}).",
        f"Objects land in /Common/Shared/, which is where a /Common virtual "
        f"server such as {plan['vs']} can reference them from.",
        f"This declaration does NOT attach anything to {plan['vs']}: that VS is "
        f"not AS3-managed, and AS3 will not modify objects it does not own. "
        f"Attach with the three tmsh commands in the tmsh artifact (STEP 8), or "
        f"move the VS into AS3.",
        "AS3's forward action has no fallback-pool equivalent, so the per-rule "
        "fallback to "
        + (plan["default_pool"] if plan["default_pool"]
           else f"the pool on {plan['vs']}")
        + " present in the tmsh artifact is not reproduced here. Traffic still "
          "reaches the app when no rule matches -- the difference is only when "
          "the bot pool is down.",
    ] + plan["warnings"]

    decl = {
        "class": "AS3",
        "action": "deploy",
        "persist": True,
        "declaration": {
            "class": "ADC",
            "schemaVersion": AS3_SCHEMA_VERSION,
            "id": f"xcbot-{plan['vs']}-{m['policy']}",
            "label": f"F5 XC Bot Defense steering for {plan['vs']}",
            "remark": notes[0][:64],
            "Common": {"class": "Tenant", "Shared": app},
        },
        "_notes": notes,
    }
    return json.dumps(decl, indent=2)
