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
F5 Bot Defense in REVERSE_PROXY mode is a service the BIG-IP steers traffic
into; the BIG-IP does not evaluate bot policy itself. Two independent jobs:

  Steering (LTM policy, first-match -- the order IS the logic)
      rule 0  path contains <js data-group>                    -> bot pool
      rule 1  <guard hdr> exists AND source in <egress dg>     -> no action
      rule 2+ method + path <op> <dg>                          -> bot pool,
                                                                 fallback app pool
      no match                                                 -> VS default pool

    Rule 0 first and unconditional: the telemetry script is always served by the
    Bot Defense service. That path is terminated by the service rather than
    proxied to the origin, so it never comes back as return traffic.

    Rule 1 is the loop guard, and it only has to precede the endpoint rules.
    "Steer to the bot pool unless the request is from an egress address AND
    carries the header" is a NAND, and an LTM rule can only AND its conditions,
    so the positive case is matched here and stopped. Carrying no action,
    first-match ends evaluation and the request proceeds to the VS's own pool.

    Both halves of rule 1 matter. The guard header alone is a value any client
    can set, so a header-only guard lets a crafted request skip Bot Defense
    entirely; pairing it with the service's egress addresses closes that. When
    the infra advertises no egress addresses we fall back to testing the header
    on each endpoint rule instead, and say so.

    The header's name is the service's to choose, not ours, so it is a
    parameter (`shape_header`, `--shape-header`) with `shape-header` as the
    default rather than a constant. Nothing downstream hardcodes it.

  Injection (HTML profile + iRule)
      The telemetry <script> is injected into the <head> of responses, but only
      on entrypoints. The iRule disables the HTML profile by default and
      re-enables it per response, so the parser never runs on traffic that does
      not need it.

      Which pages are entrypoints does NOT come from XC -- see
      _entrypoint_records. The operator supplies the list, or the data group
      gets "/" and the script goes into every HTML response.

Object names, endpoint paths and methods come from XC. The virtual server, the
entrypoint list, the default pool and the name prefix come from the operator.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import re

# Operator names are shared verbatim by tmsh and AS3 -- only negation differs,
# because AS3 folds it into the operator instead of using a `not` keyword.
_OP_AS3_NEG = {"equals": "does-not-equal", "starts-with": "does-not-start-with",
               "ends-with": "does-not-end-with", "contains": "does-not-contain"}
_OP_ORDER = {"equals": 0, "starts-with": 1, "ends-with": 2, "contains": 3}

# Placeholder for "the pool already attached to the virtual server". The tmsh
# script substitutes it on the box, where that answer is authoritative and free
# to obtain -- so nobody has to retype a pool name the VS already knows.
FALLBACK_TOKEN = "__XCBOT_VS_POOL__"


DEFAULT_PARTITION = "Common"


def qualified(partition: str, name: str) -> str:
    """`name` as tmsh must see it from the default folder.

    Objects are created inside the target partition rather than shared out of
    /Common, so every name tmsh reads or writes has to be absolute -- a bare
    name resolves in the *current* folder, which for a root shell is /Common,
    and `modify ltm virtual <bare>` on a VS in /prod fails outright with
    "The requested Virtual Server (/Common/<bare>) was not found".

    /Common is left bare: that IS the default folder, so qualifying it would
    change every existing artifact for no behavioural gain. A name that is
    already absolute is returned untouched -- pool names read off a virtual
    server arrive that way, and may legitimately point somewhere else.
    """
    if not name or name.startswith("/"):
        return name
    part = (partition or DEFAULT_PARTITION).strip("/")
    return name if part == DEFAULT_PARTITION else f"/{part}/{name}"


def fingerprint(*parts: str) -> str:
    """Short content hash, stored on the object so a later run recognises it.

    Every generated object carries `description "xcbot:<this>"`, which answers
    one question the generated script cannot otherwise answer: did this tool
    create the object of that name, or did somebody else? Content is compared
    separately and is what decides reuse -- the marker only decides whether the
    script says "reusing yours" or "reusing someone else's".

    `ltm rule` is the exception: it has no description property (measured on
    17.5.1), so its marker is a comment in the rule body instead.

    Hashed over the object's own content only. Anything that changes per build
    without changing behaviour -- the generation timestamp above all -- has to
    be left out, or no two builds ever agree.
    """
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode())
        h.update(b"\0")
    return h.hexdigest()[:12]


def fingerprints(plan: dict) -> dict[str, str]:
    """{bare object name: the sha12 this build stamps on it}.

    One computation with two readers. The generated script compares these
    markers on the box; `xcbot.py`'s build-time collision check compares the
    same ones over REST, so that the warning a human sees before deploying and
    the decision the script makes at deploy time cannot disagree. Anything that
    recomputed them separately would drift the first time a property was added
    to a comparison.

    Keyed on the bare name because that is what `names_for()` deals in; the
    caller qualifies.

    The last two are read back out of text rather than hashed here: the iRule
    stamps itself in `build_irule()` (its marker is a body comment, since
    `ltm rule` has no description), and the policy in `_policy_block()`, which
    hashes the whole rendered block. Re-deriving either would mean keeping a
    second copy of how the text is built.
    """
    part = plan["partition"]

    def q(name: str) -> str:
        return qualified(part, name)

    mon, pool = plan["monitor"], plan["pool"]
    hr, hp = plan["html_rule"], plan["html_profile"]
    fps = {
        mon["name"]: fingerprint(str(mon["interval"]), str(mon["timeout"]),
                                 mon["send"]),
        pool["name"]: fingerprint(pool["host"], str(pool["port"]),
                                  q(pool["monitor"])),
        hr["name"]: fingerprint(hr["tag"], _tmsh_str(hr["content"])),
        hp["name"]: fingerprint(" ".join(hp["content_selection"]),
                                q(hp["rule"])),
        plan["irule"]["name"]: re.search(r"# xcbot-fingerprint: ([0-9a-f]+)",
                                         plan["irule"]["text"]).group(1),
        plan["policy"]["name"]: re.search(r'description "xcbot:([0-9a-f]+)"',
                                          _policy_block(plan)).group(1),
    }
    if plan["oneconnect"]:
        fps[plan["oneconnect"]["name"]] = fingerprint(
            plan["oneconnect"]["source_mask"])
    for dg in plan["datagroups"]:
        fps[dg["name"]] = fingerprint(dg["name"], dg.get("type", "string"))
    return fps


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


# Whole-application fallback for the injection data-group. Every path contains
# "/", and the iRule matches entrypoints with `contains`, so this one record
# enables the HTML profile on every HTML response the VS returns.
ENTRYPOINT_ALL = "/"


def _entrypoint_records(paths, methods: str = "GET") -> list[tuple[str, str]]:
    """(path, methods) records for the JS-injection data-group.

    NOT derived from XC, deliberately. The policy records which endpoints are
    protected; it does not record which pages have to carry the telemetry
    script. Those are the pages holding the form (or the JS) that fires a
    protected endpoint -- a property of the application's HTML that nothing in
    the API describes. GET_DOCUMENT looks like the answer and is not: it marks
    endpoints XC expects to serve a document, not injection sites.

    So the list comes from the operator. With none given, the data group gets
    "/" and the script goes everywhere: too wide, but it cannot miss a page,
    which is the right way round for a fallback. Either way this data group is
    maintained by hand from then on.

    Keys are lowercased because the iRule lowercases the request path before
    matching. The value holds the methods, which the iRule tests with a
    substring check -- that is why they are comma-joined rather than a list.
    """
    verbs = ",".join(sorted({m.strip().upper()
                             for m in (methods or "").split(",")
                             if m.strip()})) or "GET"
    out: list[tuple[str, str]] = []
    seen = set()
    for p in (list(paths) or [ENTRYPOINT_ALL]):
        key = (p or "").strip().lower()
        if key and key not in seen:
            seen.add(key)
            out.append((key, verbs))
    return out or [(ENTRYPOINT_ALL, verbs)]


# TCL commands that pick a destination themselves. Any of these in an iRule on
# the target VS overrides this policy's forward action -- verified on 17.5.1 at
# HTTP_REQUEST priorities 100, 500 and 999, the iRule winning at all three.
_POOL_CMDS = ("pool", "node", "virtual", "LB::reselect", "LB::detach")


def irule_selects_pool(body: str) -> list[str]:
    """Destination-selecting commands used by an iRule body.

    A deliberately blunt scan: comment lines are dropped and the rest is tested
    for each command at statement position. It feeds a warning, not a decision,
    so a false positive costs a sentence of reading and a false negative costs
    silently uninspected traffic.
    """
    text = "\n".join(line.strip() for line in (body or "").splitlines()
                     if not line.strip().startswith("#"))
    return [cmd for cmd in _POOL_CMDS
            if re.search(r"(?:^|[{;\]]\s*)" + re.escape(cmd) + r"\s",
                         text, re.M)]


def build_irule(plan: dict, dg_entry: str = "") -> str:
    """The injection-scoping iRule. Behaviour matches the validated reference
    rule; the data-group name and the log switch are the only parameters.

    `dg_entry` overrides the entrypoint data group's name, because the name has
    to be the path the data group will actually have -- and that differs per
    artifact. `class match` resolves the name against the folder of the VIRTUAL
    SERVER, not of the iRule, and it does not search: measured on 17.5.1 with
    the rule and data group both in /part/Shared and the VS in /part, only the
    full /part/Shared/name resolves. A bare name and /part/name both raise a TCL
    error, which aborts the event. So tmsh and the GUI, which put the data group
    beside the virtual server, get /part/name (bare in /Common), while AS3, which
    puts it in the tenant's Shared application, gets /tenant/Shared/name.
    """
    n = dict(plan["names"])
    n["dg_entry"] = dg_entry or qualified(plan["partition"], n["dg_entry"])
    body = f"""# This rule does NOT steer traffic -- the LTM policy {n['policy']} does that.
# Its job is to keep the HTML parser off every response that does not need it:
# the HTML profile is disabled by default and enabled only for responses to a
# request whose path is listed in the {n['dg_entry']} data group.
when RULE_INIT {{
    # 1 = log every request decision to /var/log/ltm, 0 = silent.
    # Leave at 1 while validating, then set to 0 and reload the rule.
    set static::botdefense_debug 1
    # Entrypoint paths + their methods, matched with `contains`. XC does not
    # say which pages need the script, so this data group is maintained by
    # hand: add a record per page, and drop the "/" catch-all once you have.
    # Changing the injection scope means editing the data group, not this rule.
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
    # The two header lines are excluded from the fingerprint on purpose: the
    # timestamp changes on every build, and the XC policy version can change
    # without changing a byte of what the rule does. Hashing either would mean
    # a re-run never recognises the rule it wrote last time.
    return (f"# Generated by xcbot.py -- {plan['meta']['generated']}\n"
            f"# Source: XC {plan['meta']['namespace']}/{plan['meta']['policy']}"
            f" v{plan['meta']['version']}\n"
            f"# xcbot-fingerprint: {fingerprint(body)}\n"
            f"{body}")


def build_plan(inputs: dict, *, vs: str, default_pool: str = "",
               prefix: str = "bot-defense", shape_header: str = "shape-header",
               partition: str = "Common", inject_tag: str = "head",
               merge_op: str = "",
               oneconnect_mask: str = "255.255.255.255",
               entrypoints=(), entrypoint_methods: str = "GET",
               pool_selecting_irules=()) -> dict:
    """Every decision that turns XC data + operator answers into objects.

    `default_pool` is optional and feeds exactly one property: the per-rule
    `fallback-pool`, which is what a matched request falls back to when the bot
    pool has no available member. Traffic that matches no rule already reaches
    the application through the virtual server's own pool, so the name is never
    needed for that.

    Left empty, the tmsh script reads the pool off the virtual server when it
    runs, so the fallback is right without anyone naming it. Pass it only to
    override that, or when generating for a VS that does not exist yet.

    `entrypoints` are the paths whose HTML response gets the <script>. Empty
    means "not mapped": the data group gets "/" and the script goes into every
    HTML response. See _entrypoint_records for why this cannot come from XC.

    `pool_selecting_irules` is [(name, [commands])] for iRules already on the
    VS that choose a destination themselves. Those beat this policy, so their
    presence is a reason not to use it.

    `shape_header` is the header Bot Defense sets on traffic it hands back, and
    it is the whole of rule 1's first condition. Configurable because the name
    is the service's, not ours: a tenant whose deployment sends something else
    needs the guard to match that instead. Get it wrong and nothing errors --
    rule 1 simply never matches, and every protected endpoint loops.
    """
    partition = (partition or DEFAULT_PARTITION).strip().strip("/")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", partition):
        raise ValueError(
            f"partition {partition!r} is not a valid BIG-IP partition name: "
            f"letters, digits, '.', '-' and '_' only, no '/'.")

    # RFC 9110 field-name token. Worth checking here rather than trusting the
    # caller: this string is written unquoted into the policy's `name <hdr>`
    # line, so a space in it silently becomes a second tmsh keyword and an
    # empty one drops the condition's name entirely. Either way the failure
    # lands at `load sys config merge` time, on a box, in a change window.
    shape_header = (shape_header or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9!#$%&'*+.^_`|~-]+", shape_header):
        raise ValueError(
            f"--shape-header {shape_header!r} is not a valid HTTP header name: "
            f"letters, digits and !#$%&'*+-.^_`|~ only -- no spaces, no colon, "
            f"and not empty.")

    n = names_for(prefix)
    xc = inputs["xc"]
    svc = inputs["bot_service"]
    js = inputs["js"]
    hc = svc.get("health_check") or {}

    buckets, warnings = _endpoint_buckets(inputs, n["dg_ep_prefix"], merge_op)
    entrypoints = [p for p in (entrypoints or []) if (p or "").strip()]
    entry = _entrypoint_records(entrypoints, entrypoint_methods)
    entrypoints_mapped = bool(entrypoints)

    # Bot Defense's egress addresses, from the infra object. These are what make
    # the return-traffic rule trustworthy: the guard header alone is a value any
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
    datagroups.append({
        "name": n["dg_entry"],
        "purpose": "Entrypoints: paths whose HTML response gets the <script> "
                   "injected. Key = path (lowercase), value = methods. "
                   "MAINTAINED BY HAND -- XC does not record which pages need "
                   "the script, so this is the one data group nothing "
                   "regenerates for you."
                   + ("" if entrypoints_mapped else
                      " Currently the '/' catch-all: every HTML response."),
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
    if not entrypoints_mapped:
        warnings.append(
            f"Entrypoints are not mapped, so {n['dg_entry']} holds the single "
            f"record '/'. The iRule matches entrypoints with `contains` and "
            f"every path contains '/', so the <script> is injected into EVERY "
            f"HTML response this virtual server returns and the HTML parser "
            f"runs over the whole application. Deliberate default: it cannot "
            f"miss a page. The pages that actually need it are the ones "
            f"carrying a form (or JS) that fires a protected endpoint -- XC "
            f"does not record which those are, so nothing can derive them. "
            f"Once you know them, re-run with --entrypoint PATH per page, or "
            f"add the records and delete '/' with tmsh.")
    elif any(path == "/" for path, _ in entry):
        warnings.append(
            f"One of the entrypoints given is '/', matched with `contains`, so "
            f"it is true of every path -- the rest of the {n['dg_entry']} "
            f"records make no difference and the <script> goes into every HTML "
            f"response. Drop the '/' record if that is not what you want.")
    for name, cmds in (pool_selecting_irules or []):
        warnings.append(
            f"iRule '{name}' on {vs} selects a destination itself "
            f"({', '.join(cmds)}), and an iRule beats an LTM policy's forward "
            f"action at every HTTP_REQUEST priority. For the requests it "
            f"touches this whole steering policy is bypassed: protected "
            f"endpoints reach the application uninspected, with a green pool "
            f"and a policy hit counter that still increments. WITH A "
            f"CONDITIONAL POOL SELECTION ALREADY ON THIS VS, THE LTM POLICY "
            f"APPROACH IS NOT RECOMMENDED -- use F5's currently validated "
            f"Shape connector iRule instead, which steers in TCL where it can "
            f"be ordered against '{name}' rather than competing with it. If "
            f"you keep the policy, guard '{name}' so it returns early on the "
            f"paths this policy steers, starting with the telemetry JS.")
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
        # False = nobody mapped the entrypoints, so the data group is the "/"
        # catch-all. The renderers say so rather than presenting it as derived.
        "entrypoints_mapped": entrypoints_mapped,
        "pool_selecting_irules": list(pool_selecting_irules or []),
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
    A(f"# BIG-IP setup for F5 Bot Defense — virtual server `{plan['vs']}`")
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
    attach_step = 9 if plan["oneconnect"] else 8
    A(f"All navigation below is from the BIG-IP Configuration utility. Steps "
      f"1–{attach_step - 1} create objects and change nothing about live "
      f"traffic; **step {attach_step} is the only step that affects the "
      f"virtual server**.")
    A("")
    A(f"> **Before you start** — if any iRule already on `{plan['vs']}` selects "
      f"a pool (`pool`, `node`, `virtual`, `LB::reselect`), it will override "
      f"this policy for the requests it touches, at any iRule priority. Those "
      f"requests reach the application without Bot Defense seeing them, and "
      f"nothing reports it. Check the **Resources** tab first; where that is "
      f"the case, F5's validated Shape connector iRule is the better fit than "
      f"this policy.")
    A("")
    if plan["partition"] not in ("", DEFAULT_PARTITION):
        # The GUI has no per-object partition field: the object is created in
        # whatever the Partition / Path selector says at the time. Getting this
        # wrong builds a complete, working set of objects in the wrong place.
        A(f"> **Set the partition first** — use the **Partition / Path** "
          f"selector in the top-right of the Configuration utility and switch "
          f"it to **{plan['partition']}** before Step 1. Every object below is "
          f"created in the partition that selector is showing, and the names "
          f"given are bare on purpose because that is what the GUI expects. If "
          f"the selector says `Common`, you will build the whole set in the "
          f"wrong partition and `{plan['vs']}` will not be able to use it.")
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
      "all of type **String** except where noted.")
    A("")
    for dg in plan["datagroups"]:
        A(f"### `{dg['name']}`" + ("  *(type **Address**)*"
                                   if dg.get("type") == "ip" else ""))
        A("")
        A(dg["purpose"])
        A("")
        if dg["name"] == n["dg_entry"] and not plan["entrypoints_mapped"]:
            A("This is the one table to revisit. `/` is a catch-all: the iRule "
              "matches entrypoints with `contains`, so every path matches and "
              "the `<script>` is injected into every HTML response. The pages "
              "that actually need it are the ones carrying a form (or JS) that "
              "fires a protected endpoint. XC does not record which those are, "
              "so map them against the application, add one record per page, "
              "then delete the `/` record.")
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
    A(f"{nth}. **Resources** tab: under **iRules**, click **Manage…** and move "
      f"`{plan['irule']['name']}` into *Enabled*. Order matters only against "
      f"other iRules touching `HTML::` or the response — the generated iRule "
      f"sets no pool, so it never competes for the forwarding decision.")
    nth += 1
    A(f"{nth}. **Resources** tab: under **Policies**, click **Manage…** and move "
      f"`{plan['policy']['name']}` into *Enabled*. **Last, and deliberately so** "
      f"— see below.")
    A("")
    # The GUI cannot do this as one write the way tmsh can, so the order is the
    # only protection available: the policy is what steers traffic at the bot
    # pool, and the iRule is what scopes injection and turns serverssl off for
    # the application pool. Enabling the policy last means every step that can
    # be refused has already been taken, with live traffic still untouched.
    A(f"Each of those is a separate save, so unlike the tmsh script this cannot "
      f"be applied as one transaction. That is why `{plan['policy']['name']}` "
      f"goes last: it is the step that starts steering traffic, and everything "
      f"that might be refused happens before it. If step {nth - 1} fails with "
      f"`SSL::disable in rule (...) requires an associated SERVERSSL or "
      f"CLIENTSSL or PERSIST profile`, give the virtual server one and retry — "
      f"the bot pool member is on 443, so it is needed regardless. Stop there; "
      f"do not enable the policy without the iRule.")
    A("")
    A(f"While you are on that tab, read the iRules already listed. Any of them "
      f"that runs `pool`, `node`, `virtual` or `LB::reselect` wins over "
      f"`{plan['policy']['name']}` for the requests it touches, whatever the "
      f"order — see the note at the top of this document.")
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


def _sh_sq(s: str) -> str:
    """Single-quote a value for bash, preserving it exactly.

    Used for every value the generated script compares against live config.
    Double quotes would not do: the strings involved are the ones carrying
    backslashes -- the monitor's `\\r\\n`, the injected tag's escaped quotes --
    and bash resolves `\\"` inside double quotes, so the wanted value would
    arrive at the comparison already unescaped while the live value still
    carries the backslashes tmsh stored.
    """
    return "'" + s.replace("'", "'\\''") + "'"


# Shell functions the generated script uses to decide, per object, between
# creating it, reusing it and stopping. Emitted once, verbatim.
#
# Every extractor here reads `tmsh list <object> one-line`, whose shape was
# measured on 17.5.1 rather than assumed:
#
#   ltm monitor https x-hc { ... interval 5 ... send "GET /h HTTP/1.1\r\n" ...
#                            timeout 16 }
#   ltm pool x-pool { description xcbot:ab12 members { host:https { fqdn {
#                     autopopulate enabled name host } ... } } monitor x-hc }
#   ltm data-group internal x-js { records { /common.js { } } type string }
#   ltm profile html x-js-profile { ... content-selection { text/html }
#                                   defaults-from html rules { x-js-rule } }
#
# Two properties of that format are load-bearing. A description with no spaces
# comes back UNQUOTED, so the plain scalar extractor reads it. And `list ltm
# rule <name> one-line` is not valid at all -- tmsh reads `one-line` as a
# second rule name and answers 01020036:3 -- which is why iRules are the one
# object here checked from multi-line output.
_TMSH_HELPERS = r'''
#---------------------------------------------------------------------------
#  Existence and content checks.
#
#  Every object below is checked before it is created:
#     not there              -> create it, tagged  description "xcbot:<fp>"
#     there, same content    -> reuse it, and say so if xcbot did not make it
#     there, different       -> stop, print live vs wanted, change nothing
#
#  Nothing in this script ever modifies or deletes an object that already
#  exists. Where a change is needed you are given the command and left to
#  make it yourself.
#---------------------------------------------------------------------------
XCB_CREATED=0
XCB_REUSED=0
XCB_STEP=0

# tmsh exits 1 for an object that is not there, so empty output means absent.
xcb_oneline() { tmsh -c "list $* one-line" 2>/dev/null || true; }

# One `key value` property. The [ {] anchor is what keeps a request for `name`
# from matching `tag-name`.
xcb_field() { printf '%s\n' "$1" | sed -n "s/.*[ {]$2 \([^ }]*\).*/\1/p"; }

# One double-quoted property: the monitor send string.
xcb_qfield() { printf '%s\n' "$1" | sed -n "s/.*[ {]$2 \"\([^\"]*\)\".*/\1/p"; }

# The same, for a value that contains escaped double quotes of its own -- the
# injected <script src=\"...\"> tag is stored exactly like that, so stopping at
# the first quote would return half of it. This takes everything up to the LAST
# quote on the line instead, which is correct for an object whose only quoted
# property is the one being read.
xcb_qlast() { printf '%s\n' "$1" | sed -n "s/.*[ {]$2 \"\(.*\)\".*/\1/p"; }

# The contents of a `key { a b c }` block, sorted -- order is not a difference.
xcb_list() {
  printf '%s\n' "$1" | sed -n "s/.*[ {]$2 { \([^}]*\)}.*/\1/p" \
    | tr ' ' '\n' | sed '/^$/d' | sort | tr '\n' ' ' | sed 's/ $//'
}

# The names inside a nested block (policy rules, a virtual server's profiles).
# One-line output cannot be parsed here -- the entries have braces of their own
# -- so this reads the multi-line form, where tmsh indents four spaces a level.
xcb_names() {
  tmsh -c "list $1" 2>/dev/null | sed -n "/^    $2 {/,/^    }/p" \
    | grep -E '^        [^ ]+ \{' | awk '{print $1}' | sort | tr '\n' ' ' \
    | sed 's/ $//'
}

# Is $1 in the space-separated list $2? Compared on the last path element, so
# a partition-qualified name and a bare one are the same profile.
xcb_has() {
  _n=${1##*/}
  for _x in $2; do
    if [ "${_x##*/}" = "$_n" ]; then return 0; fi
  done
  return 1
}

xcb_norm() { printf '%s' "$1" | tr -s ' \t' ' ' | sed 's/^ //; s/ $//'; }

# Every value of a property that occurs more than once -- a policy names a pool
# once per rule -- as a sorted set. The [ {] anchor is doing real work again:
# without it, asking for `pool` also collects every `fallback-pool`.
xcb_multi() {
  printf '%s\n' "$1" | grep -oE "[ {]$2 [^ }]+" | awk '{print $NF}' \
    | sort -u | tr '\n' ' ' | sed 's/ $//'
}

# A pool member's port comes back as its /etc/services name where it has one:
# :443 lists as :https. Resolved back through that same table before comparing,
# so a build that asked for 443 recognises the member it created. A port with
# no name is already a number and passes straight through.
xcb_port() {
  case "$1" in
    ''|*[!0-9]*)
      awk -v s="$1" '
        /^[ \t]*#/ { next }
        $2 ~ /^[0-9]+\/tcp$/ {
          for (i = 1; i <= NF; i++) {
            if ($i == "#") break
            if (i != 2 && $i == s) { split($2, a, "/"); print a[1]; exit }
          }
        }' /etc/services ;;
    *) printf '%s\n' "$1" ;;
  esac
}

xcb_begin() { XCB_DIFF=""; XCB_DESC=""; XCB_HINT=""; XCB_UKIND=""; XCB_UPAT=""; }

# Record one differing property. Compared with runs of whitespace collapsed,
# reported verbatim -- the raw value is what has to be fixed.
xcb_cmp() {
  if [ "$(xcb_norm "$2")" != "$(xcb_norm "$3")" ]; then
    XCB_DIFF="$XCB_DIFF
      $1
          live: $2
          want: $3"
  fi
}

# What else on the box points at this object, so that reusing something the
# tool did not create names whose it is.
#  The object name is the last field before the opening brace, which is field 3
#  for a pool or a virtual and field 4 for a profile -- so it is taken as $NF of
#  the truncated line rather than by position.
xcb_users() {
  _u=$(tmsh -c "list $XCB_UKIND one-line" 2>/dev/null \
       | grep -F -- "$XCB_UPAT" | sed 's/ {.*//' | awk '{print $NF}' \
       | sort -u | tr '\n' ' ' | sed 's/ $//')
  if [ -n "$_u" ]; then echo "        Used by: $_u"; fi
}

xcb_created() { echo "  created"; XCB_CREATED=$((XCB_CREATED + 1)); }

# A wrong-typed data group is fatal where every other difference is reported:
# the policy condition that reads it is written for one type, and a string
# condition against an ip data group does not error, it simply never matches --
# so the requests it was meant to catch reach the application uninspected and
# the pool stays green. That is the one difference here worth stopping for.
# $1 wanted type, $2 live.
xcb_dgtype() {
  _t=$(xcb_field "$2" type)
  if [ "$_t" != "$1" ]; then
    echo "    exists, but is a $_t data group, not $1." >&2
    echo "    The policy reads it as $1. Against the wrong type the condition" >&2
    echo "    never matches, so requests reach the application uninspected" >&2
    echo "    while the pool stays green. Rename it, or build with a" >&2
    echo "    different --prefix." >&2
    echo "  ABORTED at step $XCB_STEP. Nothing has been changed." >&2
    exit 1
  fi
}

xcb_dgnote() {
  case "$(xcb_field "$1" description)" in
    xcbot:*) ;;
    *) echo "    NOTE: not created by xcbot (no xcbot marker)." ;;
  esac
}

# Data-group records, reported and never touched. They are legitimately edited
# by hand between runs, and reconciling them against XC belongs to
# `xcbot.py sync`, which asks before it writes. So this prints the delta and
# leaves the data group exactly as it is -- $1 name, $2 wanted keys, $3 live.
xcb_dg() {
  printf '%s\n' "$3" \
    | sed -n 's/^.* records { \(.*\) } type .*$/\1/p' \
    | grep -oE '[^ {}]+ \{' | sed 's/ {$//' | sort > "$TMP/dg.live"
  printf '%s\n' "$2" | tr ' ' '\n' | sed '/^$/d' | sort > "$TMP/dg.want"
  _n=$(grep -c . "$TMP/dg.live" || true)
  _add=$(comm -23 "$TMP/dg.want" "$TMP/dg.live")
  _del=$(comm -13 "$TMP/dg.want" "$TMP/dg.live")
  _d=$(printf '%s\n%s\n' "$_add" "$_del" | grep -c . || true)
  if [ "$_d" = 0 ]; then
    echo "    exists with $_n record(s), all of them in this build"
  else
    echo "    exists with $_n record(s), $_d not shared with this build:"
    for _k in $_add; do echo "      + $_k   (in the build, not on the box)"; done
    for _k in $_del; do echo "      - $_k   (on the box, not in the build)"; done
    echo "    left as-is. Records are reconciled, with an approval step, by:"
    echo "      xcbot.py sync --check"
  fi
  XCB_REUSED=$((XCB_REUSED + 1))
}

xcb_verdict() {
  if [ -n "$XCB_DIFF" ]; then
    echo "  $1 exists, but does not match this build:" >&2
    echo "$XCB_DIFF" >&2
    echo "" >&2
    echo "  Not modified. This script does not change objects it finds." >&2
    if [ -n "$XCB_HINT" ]; then
      echo "  To converge it yourself:" >&2
      echo "    $XCB_HINT" >&2
    fi
    echo "  Or re-run  build  with a different --prefix, for a separate set" >&2
    echo "  of objects that collides with nothing." >&2
    echo "  ABORTED at step $XCB_STEP. Nothing has been changed." >&2
    exit 1
  fi
  echo "  exists and matches this build -- reusing it"
  case "$XCB_DESC" in
    xcbot:*) ;;
    *)
      echo "  NOTE: not created by xcbot (no xcbot marker)."
      echo "        Something else on this box owns it; a change made there"
      echo "        changes how this deployment behaves."
      if [ -n "$XCB_UKIND" ]; then xcb_users; fi ;;
  esac
  XCB_REUSED=$((XCB_REUSED + 1))
}

# Same stop, for the objects that go in through `load sys config merge`. That
# command does not refuse an object that already exists -- it overwrites it
# without a word -- so for those the check is the only thing standing between
# a re-run and a silently replaced iRule.
xcb_stop_merge() {
  echo "  $1 exists, and is not what this build would write:" >&2
  echo "$XCB_DIFF" >&2
  echo "" >&2
  echo "  'load sys config merge' would have overwritten it silently." >&2
  echo "  Not doing that. This build's version is kept at:" >&2
  echo "    $2" >&2
  # The whole live object alongside it. For the policy especially, the field
  # comparison above can only name what it was told to look at, and a diff of
  # the two files is the answer to "so what actually differs".
  tmsh -c "list $3" > "$2.live" 2>/dev/null || true
  if [ -s "$2.live" ]; then
    echo "  and the live one, for a diff, at:" >&2
    echo "    $2.live" >&2
  fi
  echo "  Apply this build's version over the live one only if that is what" >&2
  echo "  you want:" >&2
  echo "    tmsh load sys config merge file $2" >&2
  echo "  Or re-run  build  with a different --prefix." >&2
  echo "  ABORTED at step $XCB_STEP. Nothing has been changed." >&2
  exit 1
}
'''


def _tmsh_records(records: list[tuple[str, str]]) -> str:
    out = []
    for k, v in records:
        out.append(f"{k} {{ data {v} }}" if v else f"{k} {{ }}")
    return " ".join(out)


def _tmsh_conditions(rule: dict, indent: str,
                     part: str = DEFAULT_PARTITION) -> list[str]:
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
            # Client address, matched at the HTTP request event. No event
            # keyword is written because `request` IS the default: on 17.5.1,
            # `tcp request address` and `tcp address` store byte-identically,
            # while `tcp client-accepted address` is kept verbatim -- so an
            # omitted event reads back the way it was typed and any other one
            # does not.
            #
            # Request rather than client-accepted deliberately. The address
            # itself is the same at either event (it is fixed when the
            # connection is established), so this is not about which address
            # gets compared -- it is about when the rule can match. The rule
            # ANDs this with the loop-guard `<header> exists`, only knowable at
            # request time, so pinning half of it to connection setup buys
            # nothing and would make the two halves evaluate on different
            # clocks once keep-alive and OneConnect are in play.
            lines.append(f"{indent}    tcp")
            lines.append(f"{indent}    address")
            if c.get("negate"):
                lines.append(f"{indent}    not")
            lines.append(f"{indent}    matches")
            lines.append(f"{indent}    datagroup {qualified(part, c['dg'])}")
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
            lines.append(f"{indent}    datagroup {qualified(part, c['dg'])}")
        lines.append(f"{indent}}}")
    return lines


def _policy_block(plan: dict) -> str:
    p = plan["policy"]
    part = plan["partition"]
    # A tcp condition makes the policy require the tcp module as well as http.
    needs_tcp = any(c["kind"] == "src-ip"
                    for r in p["rules"] for c in r["conditions"])
    # The strategy is a /Common object. Bare resolves there from /Common only,
    # so it is named absolutely for any other partition.
    strategy = (p["strategy"] if part in ("", DEFAULT_PARTITION)
                else f"/{DEFAULT_PARTITION}/{p['strategy']}")
    L = [f"ltm policy {qualified(part, p['name'])} {{",
         "    controls { forwarding }",
         "    requires { http tcp }" if needs_tcp else "    requires { http }",
         f"    strategy {strategy}",
         "    rules {"]
    for ordinal, r in enumerate(p["rules"]):
        # Rule names are scoped to the policy, not the folder: never qualified.
        L.append(f"        {r['name']} {{")
        L.append(f"            ordinal {ordinal}")
        L.append("            conditions {")
        L += _tmsh_conditions(r, "                ", part)
        L.append("            }")
        # No pool means no action: under first-match the rule still matches and
        # stops evaluation, so the request falls through to the VS's own pool.
        if r["pool"]:
            L.append("            actions {")
            L.append("                0 {")
            L.append("                    forward")
            L.append("                    select")
            if r["fallback"]:
                # The token is substituted by the script with a name read off
                # the VS, which comes back already absolute -- qualifying the
                # placeholder itself would corrupt the sed pattern.
                fb = (r["fallback"] if r["fallback"] == FALLBACK_TOKEN
                      else qualified(part, r["fallback"]))
                L.append(f"                    fallback-pool {fb}")
            L.append(f"                    pool {qualified(part, r['pool'])}")
            L.append("                }")
            L.append("            }")
        L.append("        }")
    L += ["    }", "}"]
    # Fingerprinted with the fallback-pool placeholder still in it. The real
    # pool name is substituted on the box from whatever the virtual server
    # carries, so it is not knowable here -- and a policy whose only difference
    # is a fallback pool that moved is not a policy this build should refuse to
    # recognise. The script compares the live fallback-pool separately.
    fp = fingerprint("\n".join(L))
    L.insert(1, f'    description "xcbot:{fp}"')
    return "\n".join(L)


def render_tmsh(plan: dict) -> str:
    m, n = plan["meta"], plan["names"]
    part = plan["partition"]
    in_partition = part not in ("", DEFAULT_PARTITION)

    def q(name: str) -> str:
        return qualified(part, name)

    vsq = q(plan["vs"])
    # The markers stamped on each object, shared with the build-time collision
    # check so the two cannot disagree about what this build's version is.
    FP = fingerprints(plan)
    total = 10 if plan["oneconnect"] else 9
    total += 1              # preflight, always: see below
    attach = total - 1
    L = []
    A = L.append
    A("#!/bin/bash")
    A("#" + "=" * 74)
    A("#  BIG-IP configuration for F5 Bot Defense")
    A(f"#  Virtual server : {vsq}   (fallback pool: "
      + (plan["default_pool"] if plan["default_pool"]
         else "read off the VS at run time") + ")")
    A(f"#  Partition      : {part}"
      + ("" if in_partition else "  (the default folder)"))
    A(f"#  XC source      : {m['namespace']}/{m['policy']} v{m['version']} "
      f"via infra {m['infra']}")
    A(f"#  Generated      : {m['generated']} by xcbot.py")
    A("#" + "=" * 74)
    A("#")
    A("#  Run on the BIG-IP as root:   bash " + f"{plan['vs']}_botdefense.sh")
    A("#  Or copy the text inside each  tmsh -c '...'  into an interactive tmsh")
    A("#  shell, one step at a time.")
    A("#")
    A(f"#  Steps 1-{attach - 1} only create objects -- live traffic is "
      f"untouched until")
    A(f"#  STEP {attach} attaches them to the virtual server.")
    A("#")
    A(f"#  BEFORE STEP {attach}: check what {vsq} already runs.")
    A(f"#    tmsh list ltm virtual {vsq} rules")
    A("#  Any iRule there that runs pool / node / virtual / LB::reselect")
    A("#  overrides this policy for the requests it touches, at every iRule")
    A("#  priority. Those requests reach the application uninspected while the")
    A("#  pool stays green. Where that is the case, F5's validated Shape")
    A("#  connector iRule is the better fit than this policy.")
    A("#")
    A("#  SAFE TO RE-RUN. Every step checks for the object first: absent means")
    A("#  create, present with the same content means reuse, present with")
    A("#  different content means stop and tell you. Nothing here modifies or")
    A("#  deletes an object that already exists, so a partly-built box can be")
    A("#  finished by running this again.")
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
    # Anything a mismatch report needs to survive the trap is written here
    # instead. $TMP is deleted on the way out, including on the abort path.
    A('KEEP=/var/tmp')
    A(_TMSH_HELPERS)

    step = 1

    # Everything after this creates objects. A name that does not resolve is
    # worth catching before the first of them exists, not nine steps later.
    A(f'echo "== STEP {step}/{total} -- preflight =="')
    if in_partition:
        A(f"tmsh -c 'list auth partition {part}' >/dev/null 2>&1 || {{")
        A(f'  echo "  partition {part} does not exist on this BIG-IP." >&2')
        A(f'  echo "  Create it first:  tmsh create auth partition {part}" >&2')
        A("  exit 1")
        A("}")
    A(f"tmsh -c 'list ltm virtual {vsq}' >/dev/null 2>&1 || {{")
    A(f'  echo "  no virtual server {vsq}." >&2')
    A(f'  echo "  Check the name and partition:  tmsh -c \'cd /{part};'
      f' list ltm virtual\'" >&2')
    A("  exit 1")
    A("}")
    A(f'echo "  {vsq} found"')
    # A virtual server takes at most one profile of a given type. A second HTML
    # profile is refused with '01070097:3: ... lists duplicate profiles', and a
    # second one-connect the same way -- at the attach step, with every object
    # already created. Both are knowable here, before anything exists.
    A(f'VSPROF=$(xcb_names "ltm virtual {vsq}" profiles)')
    A('echo "  profiles already on it: ${VSPROF:-<none>}"')
    # An HTML profile is only accepted on a virtual server that has an HTTP
    # profile: without one, `profiles add` is refused with '01070734:3: Required
    # profile profile_http not present'. Measured at the attach step on 17.5.1
    # against a VS carrying clientssl, serverssl and tcp -- which is to say
    # after all nine objects had been created for nothing.
    A("XCB_T=$(tmsh -c 'list ltm profile http one-line' 2>/dev/null "
      "| awk '{print $4}' | tr '\\n' ' ' || true)")
    A('XCB_HTTP=""')
    A('for _p in $VSPROF; do')
    A('  if xcb_has "$_p" "$XCB_T"; then XCB_HTTP="$_p"; fi')
    A('done')
    A('if [ -z "$XCB_HTTP" ]; then')
    A(f'  echo "  {vsq} has no HTTP profile." >&2')
    A('  echo "  An HTML profile cannot be attached without one, so step '
      f'{attach} would be" >&2')
    A('  echo "  refused after this script had created everything else. '
      'Stopping" >&2')
    A('  echo "  while nothing exists." >&2')
    A(f'  echo "    tmsh modify ltm virtual {vsq} profiles add {{ http }}" >&2')
    A('  echo "  Worth a look at the virtual server first, though: one with no '
      'HTTP" >&2')
    A('  echo "  profile is not parsing HTTP at all, so neither this policy\'s '
      'path" >&2')
    A('  echo "  conditions nor the script injection could work on it." >&2')
    A(f'  echo "  ABORTED at step {step}. Nothing has been changed." >&2')
    A('  exit 1')
    A('fi')
    A('echo "  HTTP profile: $XCB_HTTP"')
    pre = [("html", plan["html_profile"]["name"],
            ["A different --prefix will not help: the conflict is the type, not",
             "the name. Either detach that profile first, or point this build",
             "at a virtual server that has no HTML profile."])]
    if plan["oneconnect"]:
        pre.append(("one-connect", plan["oneconnect"]["name"],
                    ["This build does not need to own that profile. Re-run",
                     "build with  --oneconnect-mask ''  and the one already",
                     "there is left in place and used."]))
    for kind, want, hint in pre:
        # Field 4: 'ltm profile <kind> <name> {'.
        A(f"XCB_T=$(tmsh -c 'list ltm profile {kind} one-line' 2>/dev/null "
          f"| awk '{{print $4}}' | tr '\\n' ' ' || true)")
        A('for _p in $VSPROF; do')
        A('  if xcb_has "$_p" "$XCB_T"; then')
        A(f'    if [ "${{_p##*/}}" = "{want}" ]; then')
        A(f'      echo "  {kind} profile {want} is already attached"')
        A('    else')
        A(f'      echo "  {vsq} already carries the {kind} profile $_p." >&2')
        A(f'      echo "  A virtual server takes only one {kind} profile, so'
          f' attaching" >&2')
        A(f'      echo "  {want} at step {attach} would be refused -- after this'
          f' script had" >&2')
        A('      echo "  created everything else. Stopping while nothing '
          'exists." >&2')
        for line in hint:
            A(f'      echo "    {line}" >&2')
        A(f'      echo "  ABORTED at step {step}. Nothing has been changed." >&2')
        A('      exit 1')
        A('    fi')
        A('  fi')
        A('done')
    A("")
    step += 1

    A(f'echo "== STEP {step}/{total} -- health monitor {q(plan["monitor"]["name"])} =="')
    mon = plan["monitor"]
    mon_fp = FP[mon["name"]]
    A("XCB_STEP=" + str(step))
    A("xcb_begin")
    A(f"LIVE=$(xcb_oneline ltm monitor https {q(mon['name'])})")
    A('if [ -z "$LIVE" ]; then')
    A(f"  tmsh -c 'create ltm monitor https {q(mon['name'])} defaults-from https "
      f"interval {mon['interval']} timeout {mon['timeout']} recv none "
      f"send \"{mon['send']}\" description xcbot:{mon_fp}'")
    A("  xcb_created")
    A("else")
    # send is the property that carries the health-check path and Host header,
    # so it is the one that actually decides whether this monitor is checking
    # what this build wants checked.
    A('  XCB_DESC=$(xcb_field "$LIVE" description)')
    A('  xcb_cmp interval "$(xcb_field "$LIVE" interval)"'
      f' "{mon["interval"]}"')
    A('  xcb_cmp timeout  "$(xcb_field "$LIVE" timeout)"'
      f' "{mon["timeout"]}"')
    A('  xcb_cmp send     "$(xcb_qfield "$LIVE" send)"'
      f' {_sh_sq(mon["send"])}')
    A('  XCB_HINT=' + _sh_sq(
        f'tmsh modify ltm monitor https {q(mon["name"])}'
        f' interval {mon["interval"]} timeout {mon["timeout"]}'
        f' send "{mon["send"]}"'))
    # Whose monitor it is, if it is not ours: every pool that health-checks
    # with it. Editing it later changes those pools too.
    A('  XCB_UKIND="ltm pool"')
    # Space-delimited rather than 'monitor <name>': a pool can carry a monitor
    # rule ('min 1 of { /Common/x }') where the name is not the word after
    # 'monitor'. Over-matching here would name one pool too many in a note;
    # under-matching would name none.
    A(f'  XCB_UPAT=" {q(mon["name"])} "')
    A(f'  xcb_verdict "health monitor {q(mon["name"])}"')
    A("fi")
    A("")

    step += 1
    A(f'echo "== STEP {step}/{total} -- pool {q(plan["pool"]["name"])} =="')
    pool = plan["pool"]
    pool_fp = FP[pool["name"]]
    A("XCB_STEP=" + str(step))
    A("xcb_begin")
    A(f"LIVE=$(xcb_oneline ltm pool {q(pool['name'])})")
    A('if [ -z "$LIVE" ]; then')
    A(f"  tmsh -c 'create ltm pool {q(pool['name'])} monitor {q(pool['monitor'])} "
      f"members add {{ {pool['host']}:{pool['port']} {{ fqdn {{ autopopulate "
      f"enabled name {pool['host']} }} }} }} description xcbot:{pool_fp}'")
    A("  xcb_created")
    A("else")
    A('  XCB_DESC=$(xcb_field "$LIVE" description)')
    # The member is read as host:port out of the one-line text rather than by
    # name. An FQDN pool whose name has resolved holds TWO members -- the
    # template plus an ephemeral <host>_auto_<ip>:port -- so the member NAMES
    # differ between a fresh pool and a resolved one while the pool is the
    # same pool. What has to match is the hostname, the port and the monitor.
    A(f'  MEM=$(printf \'%s\' "$LIVE" | grep -oE '
      f'" {pool["host"].replace(".", chr(92) + ".")}:[a-zA-Z0-9-]+ " '
      f'| head -1 | tr -d " ")')
    A('  if [ -n "$MEM" ]; then')
    A('    MEM="${MEM%:*}:$(xcb_port "${MEM##*:}")"')
    A('  else')
    A(f'    MEM="(no member named {pool["host"]})"')
    A('  fi')
    A(f'  xcb_cmp member "$MEM" "{pool["host"]}:{pool["port"]}"')
    A('  xcb_cmp monitor "$(xcb_field "$LIVE" monitor)"'
      f' "{q(pool["monitor"])}"')
    A(f'  XCB_HINT="tmsh modify ltm pool {q(pool["name"])}'
      f' monitor {q(pool["monitor"])} members replace-all-with {{'
      f' {pool["host"]}:{pool["port"]} {{ fqdn {{ autopopulate enabled'
      f' name {pool["host"]} }} }} }}"')
    A('  XCB_UKIND="ltm virtual"')
    A(f'  XCB_UPAT=" {q(pool["name"])} "')
    A(f'  xcb_verdict "pool {q(pool["name"])}"')
    A("fi")
    A("")

    step += 1
    A(f'echo "== STEP {step}/{total} -- data groups =="')
    A(f"# {q(n['dg_entry'])} is the one you will keep editing: XC does not say")
    A("# which pages need the telemetry script, so it is maintained by hand.")
    A(f"#   tmsh modify ltm data-group internal {q(n['dg_entry'])} records add "
      f"{{ /login {{ data GET }} }}")
    if not plan["entrypoints_mapped"]:
        A("# ...and once the real pages are in, drop the catch-all:")
        A(f"#   tmsh modify ltm data-group internal {q(n['dg_entry'])} records "
          f"delete {{ / }}")
    A("XCB_STEP=" + str(step))
    for dg in plan["datagroups"]:
        dgt = dg.get("type", "string")
        dg_fp = FP[dg["name"]]
        keys = " ".join(k for k, _ in dg["records"])
        A(f"#  {q(dg['name'])}: {dg['purpose']}")
        A(f'echo "  {q(dg["name"])}"')
        A(f"LIVE=$(xcb_oneline ltm data-group internal {q(dg['name'])})")
        A('if [ -z "$LIVE" ]; then')
        A(f"  tmsh -c 'create ltm data-group internal {q(dg['name'])} "
          f"type {dgt} "
          f"records add {{ {_tmsh_records(dg['records'])} }} "
          f"description xcbot:{dg_fp}'")
        A('  echo "    created"')
        A("  XCB_CREATED=$((XCB_CREATED + 1))")
        A("else")
        A(f'  xcb_dgtype {dgt} "$LIVE"')
        if dg["name"] == n["dg_entry"]:
            # Not diffed at all. The build's record here is a placeholder --
            # '/' or whatever --entrypoint was given -- and the live list is
            # the operator's own work. A delta would be noise that reads as a
            # problem.
            A('  echo "    exists -- hand-maintained, left alone"')
            A("  XCB_REUSED=$((XCB_REUSED + 1))")
        else:
            A(f'  xcb_dg "{q(dg["name"])}" "{keys}" "$LIVE"')
        A('  xcb_dgnote "$LIVE"')
        A("fi")
    A("")

    step += 1
    A(f'echo "== STEP {step}/{total} -- HTML rule (the injected script tag) =="')
    hr = plan["html_rule"]
    A("# Merged from a file rather than created inline: tmsh -c strips the")
    A("# escaped double quotes out of the tag, leaving src=/path unquoted.")
    hr_text = _tmsh_str(hr["content"])
    hr_fp = FP[hr["name"]]
    A("cat > $TMP/htmlrule.conf <<'XCBOT_EOF'")
    A(f"ltm html-rule tag-append-html {q(hr['name'])} {{")
    A("    action {")
    A(f"        text \"{hr_text}\"")
    A("    }")
    A(f'    description "xcbot:{hr_fp}"')
    A("    match {")
    A(f"        tag-name {hr['tag']}")
    A("    }")
    A("}")
    A("XCBOT_EOF")
    A("XCB_STEP=" + str(step))
    A("xcb_begin")
    A(f"LIVE=$(xcb_oneline ltm html-rule tag-append-html {q(hr['name'])})")
    A('if [ -z "$LIVE" ]; then')
    A("  tmsh -c 'load sys config merge file '$TMP'/htmlrule.conf'")
    A("  xcb_created")
    A("else")
    A('  XCB_DESC=$(xcb_field "$LIVE" description)')
    A('  xcb_cmp tag-name "$(xcb_field "$LIVE" tag-name)"'
      f' {_sh_sq(hr["tag"])}')
    A('  xcb_cmp text "$(xcb_qlast "$LIVE" text)"' f' {_sh_sq(hr_text)}')
    A('  XCB_UKIND="ltm profile html"')
    A(f'  XCB_UPAT=" {q(hr["name"])} "')
    kept = f"$KEEP/xcbot-{plan['vs']}-{hr['name']}.conf"
    A('  if [ -n "$XCB_DIFF" ]; then')
    A(f'    cp $TMP/htmlrule.conf {kept}')
    A(f'    xcb_stop_merge "html rule {q(hr["name"])}" {kept}'
      f' "ltm html-rule tag-append-html {q(hr["name"])}"')
    A("  fi")
    A(f'  xcb_verdict "html rule {q(hr["name"])}"')
    A("fi")
    A("")

    step += 1
    A(f'echo "== STEP {step}/{total} -- HTML profile =="')
    hp = plan["html_profile"]
    cs = " ".join(hp["content_selection"])
    hp_fp = FP[hp["name"]]
    A("XCB_STEP=" + str(step))
    A("xcb_begin")
    A(f"LIVE=$(xcb_oneline ltm profile html {q(hp['name'])})")
    A('if [ -z "$LIVE" ]; then')
    A(f"  tmsh -c 'create ltm profile html {q(hp['name'])} defaults-from html "
      f"content-selection add {{ {cs} }} "
      f"rules add {{ {q(hp['rule'])} }} description xcbot:{hp_fp}'")
    A("  xcb_created")
    A("else")
    A('  XCB_DESC=$(xcb_field "$LIVE" description)')
    # Both are sets, compared sorted: the order tmsh lists them in is not
    # something this build chose or should insist on.
    A('  xcb_cmp content-selection "$(xcb_list "$LIVE" content-selection)"'
      f' {_sh_sq(" ".join(sorted(hp["content_selection"])))}')
    A('  xcb_cmp rules "$(xcb_list "$LIVE" rules)"'
      f' {_sh_sq(q(hp["rule"]))}')
    A(f'  XCB_HINT="tmsh modify ltm profile html {q(hp["name"])}'
      f' content-selection replace-all-with {{ {cs} }}'
      f' rules replace-all-with {{ {q(hp["rule"])} }}"')
    A('  XCB_UKIND="ltm virtual"')
    A(f'  XCB_UPAT=" {q(hp["name"])} "')
    A(f'  xcb_verdict "HTML profile {q(hp["name"])}"')
    A("fi")
    A("")

    if plan["oneconnect"]:
        step += 1
        oc = plan["oneconnect"]
        oc_fp = FP[oc["name"]]
        A(f'echo "== STEP {step}/{total} -- OneConnect profile {q(oc["name"])} =="')
        A("# Serverside connection reuse. The stock profile's `source-mask any`")
        A("# lets unrelated clients share a serverside connection; a /32 mask")
        A("# keeps reuse within one client address.")
        A("XCB_STEP=" + str(step))
        A("xcb_begin")
        A(f"LIVE=$(xcb_oneline ltm profile one-connect {q(oc['name'])})")
        A('if [ -z "$LIVE" ]; then')
        A(f"  tmsh -c 'create ltm profile one-connect {q(oc['name'])} "
          f"defaults-from oneconnect source-mask {oc['source_mask']} "
          f"description xcbot:{oc_fp}'")
        A("  xcb_created")
        A("else")
        A('  XCB_DESC=$(xcb_field "$LIVE" description)')
        A('  xcb_cmp source-mask "$(xcb_field "$LIVE" source-mask)"'
          f' {_sh_sq(oc["source_mask"])}')
        A(f'  XCB_HINT="tmsh modify ltm profile one-connect {q(oc["name"])}'
          f' source-mask {oc["source_mask"]}"')
        A('  XCB_UKIND="ltm virtual"')
        A(f'  XCB_UPAT=" {q(oc["name"])} "')
        A(f'  xcb_verdict "OneConnect profile {q(oc["name"])}"')
        A("fi")
        A("")

    step += 1
    A(f'echo "== STEP {step}/{total} -- iRule {q(plan["irule"]["name"])} =="')
    A("# Multi-line TCL has no single-line create form, so it is merged from a")
    A("# file. The same file is written next to this script as "
      f"{plan['irule']['name']}.tcl for the GUI path.")
    A(f"cat > $TMP/irule.conf <<'XCBOT_EOF'")
    A(f"ltm rule {q(plan['irule']['name'])} {{")
    A(plan["irule"]["text"])
    A("}")
    A("XCBOT_EOF")
    irule_fp = FP[plan["irule"]["name"]]
    A("XCB_STEP=" + str(step))
    A("xcb_begin")
    # The one object read multi-line: 'list ltm rule <name> one-line' is not a
    # valid command -- tmsh reads 'one-line' as a second rule name and answers
    # '01020036:3: The requested iRule (one-line) was not found'.
    A(f"LIVE=$(tmsh -c 'list ltm rule {q(plan['irule']['name'])}' 2>/dev/null "
      f"|| true)")
    A('if [ -z "$LIVE" ]; then')
    A("  tmsh -c 'load sys config merge file '$TMP'/irule.conf'")
    A("  xcb_created")
    A("else")
    # TCL cannot be compared by meaning, and it cannot be compared byte for byte
    # either -- the header carries a build timestamp. So the rule carries a hash
    # of its own body, and that is the whole comparison. An iRule of this name
    # without one is treated as a mismatch rather than adopted: this script has
    # no way to tell whether it does what the policy needs, and guessing wrong
    # means requests reach the application uninspected.
    A('  FP=$(printf \'%s\\n\' "$LIVE" '
      "| sed -n 's/^ *# xcbot-fingerprint: \\([0-9a-f]*\\).*/\\1/p' | head -1)")
    A('  xcb_cmp body-fingerprint'
      ' "${FP:-(none -- no xcbot-fingerprint line in the rule body)}"'
      f' {_sh_sq(irule_fp)}')
    A('  XCB_DESC="xcbot:$FP"')
    A('  XCB_UKIND="ltm virtual"')
    A(f'  XCB_UPAT=" {q(plan["irule"]["name"])} "')
    kept = f"$KEEP/xcbot-{plan['vs']}-{plan['irule']['name']}.conf"
    A('  if [ -n "$XCB_DIFF" ]; then')
    A(f'    cp $TMP/irule.conf {kept}')
    A(f'    xcb_stop_merge "iRule {q(plan["irule"]["name"])}" {kept}'
      f' "ltm rule {q(plan["irule"]["name"])}"')
    A("  fi")
    A(f'  xcb_verdict "iRule {q(plan["irule"]["name"])}"')
    A("fi")
    A("")

    step += 1
    A(f'echo "== STEP {step}/{total} -- LTM policy {q(plan["policy"]["name"])} =="')
    A("# Nested policy rules are merged for the same reason as the iRule.")
    A("# Merged policies are created published, so no separate publish is needed.")
    A("cat > $TMP/policy.conf <<'XCBOT_EOF'")
    policy_conf = _policy_block(plan)
    A(policy_conf)
    A("XCBOT_EOF")
    pol = plan["policy"]
    pol_fp = FP[pol["name"]]
    # The fallback pool is the one property of this policy that is not known at
    # build time, so the wanted set is assembled here with the placeholder still
    # in it and resolved below, alongside the substitution into the .conf.
    fb_want = sorted({(r["fallback"] if r["fallback"] == FALLBACK_TOKEN
                       else q(r["fallback"]))
                      for r in pol["rules"] if r["pool"] and r["fallback"]})
    A(f'WANTFB="{" ".join(fb_want)}"')
    if plan["fallback_from_vs"]:
        A("")
        A("# fallback-pool = the pool already attached to the VS. Read here")
        A("# rather than asked for at build time: the VS is the authority on")
        A("# its own pool, and this is where that answer is free to get.")
        A(f"FALLBACK=$(tmsh -c 'list ltm virtual {vsq} pool' "
          f"| sed -n 's/^[[:space:]]*pool //p')")
        A("# A VS with no pool prints 'pool none', not nothing. tmsh happens to")
        A("# accept 'fallback-pool none' and normalise it away, so the config")
        A("# would come out right either way -- but the operator would be told")
        A("# the fallback pool is called 'none'.")
        A('if [ "$FALLBACK" = none ]; then FALLBACK=""; fi')
        A("if [ -n \"$FALLBACK\" ]; then")
        A(f'  echo "  fallback-pool: $FALLBACK  (read from {vsq})"')
        A(f"  sed -i \"s|{FALLBACK_TOKEN}|$FALLBACK|g\" $TMP/policy.conf")
        A("else")
        A(f'  echo "  {vsq} has no pool, so the rules get no'
          f' fallback-pool:"')
        A('  echo "  a matched request will fail if the bot pool is down."')
        A(f"  sed -i '/{FALLBACK_TOKEN}/d' $TMP/policy.conf")
        A("fi")
        A(f'WANTFB=$(printf \'%s\' "$WANTFB" '
          f'| sed "s|{FALLBACK_TOKEN}|$FALLBACK|g")')
    A('WANTFB=$(printf \'%s\' "$WANTFB" | tr \' \' \'\\n\' | sed \'/^$/d\' '
      '| sort -u | tr \'\\n\' \' \' | sed \'s/ $//\')')
    A("XCB_STEP=" + str(step))
    A("xcb_begin")
    A(f"LIVE=$(xcb_oneline ltm policy {q(pol['name'])})")
    A('if [ -z "$LIVE" ]; then')
    A("  tmsh -c 'load sys config merge file '$TMP'/policy.conf'")
    A("  xcb_created")
    A("else")
    # The description hash covers the whole block, conditions included, so it is
    # the check that cannot be fooled. The three field comparisons under it exist
    # to make a mismatch report say something the operator can act on -- a bare
    # "the hash differs" is true and useless. When only the hash differs, what
    # changed is inside the conditions, and the kept .conf plus its .live
    # companion is the way to see it.
    A('  XCB_DESC=$(xcb_field "$LIVE" description)')
    A(f'  xcb_cmp content-hash "$XCB_DESC" "xcbot:{pol_fp}"')
    A(f'  xcb_cmp rules "$(xcb_names "ltm policy {q(pol["name"])}" rules)"'
      f' {_sh_sq(" ".join(sorted(r["name"] for r in pol["rules"])))}')
    A('  xcb_cmp pools "$(xcb_multi "$LIVE" pool)"'
      f' {_sh_sq(" ".join(sorted({q(r["pool"]) for r in pol["rules"] if r["pool"]})))}')
    A('  xcb_cmp fallback-pools "$(xcb_multi "$LIVE" fallback-pool)" "$WANTFB"')
    A('  XCB_UKIND="ltm virtual"')
    A(f'  XCB_UPAT=" {q(pol["name"])} "')
    kept = f"$KEEP/xcbot-{plan['vs']}-{pol['name']}.conf"
    A('  if [ -n "$XCB_DIFF" ]; then')
    A(f"    cp $TMP/policy.conf {kept}")
    A(f'    xcb_stop_merge "LTM policy {q(pol["name"])}" {kept}'
      f' "ltm policy {q(pol["name"])}"')
    A("  fi")
    A(f'  xcb_verdict "LTM policy {q(pol["name"])}"')
    A("fi")
    A("")

    step += 1
    A(f'echo "== STEP {step}/{total} -- attach to {vsq}  <-- affects live traffic =="')
    A("# 'rules' is an ordered list and REPLACES what is there, so read the")
    A("# current list first and append to it rather than overwriting.")
    A("# Read multi-line and one name per line: 'one-line' is rejected outright")
    A("# when a property is named ('unknown property'), and matching rules {...}")
    A("# in one-line output also matches a virtual server whose own name ends in")
    A("# 'rules'. A VS with no iRules prints 'rules none', which yields nothing.")
    A(f"EXISTING=$(tmsh -c 'list ltm virtual {vsq} rules' 2>/dev/null "
      f"| sed -n '/^ *rules {{/,/^ *}}/p' | sed '1d;$d' | tr -s ' \\n' ' ')")
    A(f'echo "  existing iRules on {vsq}: ${{EXISTING:-<none>}}"')
    A('if [ -n "$EXISTING" ]; then')
    A('  echo "  ^^ if any of those runs pool / node / virtual / LB::reselect,"')
    A(f'  echo "     it overrides {q(plan["policy"]["name"])} for the requests it'
      f' touches."')
    A('fi')
    profiles = [q(plan["html_profile"]["name"])]
    if plan["oneconnect"]:
        profiles.append(q(plan["oneconnect"]["name"]))
    irule = q(plan["irule"]["name"])
    # tmsh prints attached iRules with the same absolute names it accepts, so
    # the already-attached test compares like with like.
    A(f'case " $EXISTING " in')
    A(f'  *" {irule} "*)')
    A(f'    echo "  {irule} is already attached, leaving the rule list alone"')
    A('    RULES="$EXISTING" ;;')
    A(f'  *) RULES="$EXISTING {irule}" ;;')
    A('esac')
    # 'profiles' and 'policies' are sets rather than ordered lists, so they are
    # added to rather than replaced -- but re-adding one that is already there is
    # refused outright ('01020066:3'), which would abort the whole modify. So
    # each is subtracted from the live list first, and an empty 'add { }' is not
    # merely pointless but a Syntax Error, so the clause is left out entirely.
    A(f'VSPROF=$(xcb_names "ltm virtual {vsq}" profiles)')
    A(f'VSPOL=$(xcb_names "ltm virtual {vsq}" policies)')
    A('ADDPROF=""')
    for p in profiles:
        A(f'if xcb_has "{p}" "$VSPROF"; then')
        A(f'  echo "  {p} is already attached"')
        A('else')
        A(f'  ADDPROF="$ADDPROF {p}"')
        A('fi')
    A('ADDPOL=""')
    A(f'if xcb_has "{q(plan["policy"]["name"])}" "$VSPOL"; then')
    A(f'  echo "  {q(plan["policy"]["name"])} is already attached"')
    A('else')
    A(f'  ADDPOL=" {q(plan["policy"]["name"])}"')
    A('fi')
    # One modify, not three. tmsh applies a combined modify as a single
    # transaction (measured on 17.5.1), so if any part of it is refused none
    # of it is applied and the virtual server is left exactly as it was. The
    # refusal to expect is '01071912:3: SSL::disable in rule (...) requires an
    # associated SERVERSSL or CLIENTSSL or PERSIST profile' on a VS that has
    # none. Issued as three separate calls, that same failure would leave the
    # policy already steering matched requests at the bot pool with no iRule
    # to scope them -- and since the bot pool member is :443 and nothing had
    # turned serverssl off for the application pool, the VS would answer 400.
    A('MOD=""')
    A('if [ -n "$ADDPROF" ]; then MOD="$MOD profiles add {$ADDPROF }"; fi')
    A('if [ -n "$ADDPOL" ]; then MOD="$MOD policies add {$ADDPOL }"; fi')
    A('if [ "$RULES" != "$EXISTING" ]; then MOD="$MOD rules { $RULES }"; fi')
    A('if [ -z "$MOD" ]; then')
    A(f'  echo "  {vsq} already carries all of it -- nothing to change"')
    A("else")
    A(f'  tmsh -c "modify ltm virtual {vsq}$MOD"')
    A('  echo "  attached"')
    A("fi")
    A("")

    step += 1
    A(f'echo "== STEP {step}/{total} -- save =="')
    A("tmsh -c 'save sys config'")
    A("")
    A('echo "Created $XCB_CREATED object(s), reused $XCB_REUSED."')
    A(f'echo "Done. Check:  tmsh show ltm pool {q(plan["pool"]["name"])}"')
    A(f'echo "              tmsh show ltm policy {q(plan["policy"]["name"])}"')
    A(f'echo "              tail -f /var/log/ltm"')
    A("")
    A("#" + "-" * 74)
    A("# Roll back everything this script created, in this order -- the iRule")
    A("# calls HTML::disable, so it has to come off the virtual server BEFORE")
    A("# the HTML profile it depends on, or the detach is refused with")
    A("# '01071912:3: HTML::disable in rule ... requires an associated HTML")
    A("# profile on the virtual-server'.")
    A(f"#   tmsh modify ltm virtual {vsq} rules {{ }}   # then re-add yours")
    A(f"#   tmsh modify ltm virtual {vsq} policies delete "
      f"{{ {q(plan['policy']['name'])} }}")
    detach = [q(plan["html_profile"]["name"])]
    if plan["oneconnect"]:
        detach.append(q(plan["oneconnect"]["name"]))
    A(f"#   tmsh modify ltm virtual {vsq} profiles delete "
      f"{{ {' '.join(detach)} }}")
    A(f"#   tmsh delete ltm policy {q(plan['policy']['name'])}")
    A(f"#   tmsh delete ltm rule {q(plan['irule']['name'])}")
    A(f"#   tmsh delete ltm profile html {q(plan['html_profile']['name'])}")
    if plan["oneconnect"]:
        A(f"#   tmsh delete ltm profile one-connect {q(plan['oneconnect']['name'])}")
    A(f"#   tmsh delete ltm html-rule tag-append-html {q(plan['html_rule']['name'])}")
    for dg in plan["datagroups"]:
        A(f"#   tmsh delete ltm data-group internal {q(dg['name'])}")
    A(f"#   tmsh delete ltm pool {q(plan['pool']['name'])}")
    A(f"#   tmsh delete ltm monitor https {q(plan['monitor']['name'])}")
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

    # AS3 tenant == BIG-IP partition. /Common keeps the Shared application it
    # has always used; any other partition becomes a tenant of its own, which
    # is the only way AS3 can put objects where the virtual server can see them.
    part = plan["partition"]
    tenant = DEFAULT_PARTITION if part in ("", DEFAULT_PARTITION) else part

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
    # Not plan["irule"]["text"]: that names the data group where tmsh puts it,
    # beside the virtual server. AS3 puts it in this tenant's Shared application
    # instead, and `class match` resolves against the virtual server's folder
    # without searching, so the rule has to name the full /tenant/Shared/ path
    # or the lookup raises a TCL error and kills the request. Verified on 17.5.1.
    app[n["irule"]] = {
        "class": "iRule", "expand": False,
        "iRule": build_irule(plan, f"/{tenant}/Shared/{n['dg_entry']}"),
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
        f"Objects land in /{tenant}/Shared/, which is where a /{tenant} virtual "
        f"server such as {plan['vs']} can reference them from.",]
    if tenant != DEFAULT_PARTITION:
        notes.append(
            f"WARNING -- AS3 OWNS THE WHOLE TENANT IT DEPLOYS. Posting this "
            f"declaration makes AS3 authoritative for partition /{tenant}, and "
            f"it REMOVES objects in that partition that are not in the "
            f"declaration. If /{tenant} was built by hand or by another tool, "
            f"this will delete that config. /Common is exempt, which is why the "
            f"default target is safe and this one is not. Deploy the tmsh "
            f"artifact instead unless /{tenant} is already AS3-managed, or add "
            f"the existing objects to this declaration first.")
    notes += [
        f"This declaration does NOT attach anything to {plan['vs']}: that VS is "
        f"not AS3-managed, and AS3 will not modify objects it does not own. "
        f"Attach with the three tmsh commands in the tmsh artifact (STEP 8), or "
        f"move the VS into AS3.",
        f"{n['dg_entry']} is maintained by hand -- XC does not record which "
        f"pages need the telemetry script. AS3 owns this data group once "
        f"deployed, so a later redeploy REVERTS records added with tmsh or the "
        f"GUI. Keep the entrypoint list in this declaration (or in the "
        f"--entrypoint flags that generate it), not on the box."
        + ("" if plan["entrypoints_mapped"] else
           " It currently holds only the '/' catch-all, which injects into "
           "every HTML response."),
        f"If any iRule already on {plan['vs']} selects a pool, it overrides "
        f"{n['policy']} for the requests it touches at every iRule priority, "
        f"and this declaration cannot see that -- it does not read the VS. "
        f"Check `tmsh list ltm virtual {plan['vs']} rules` before attaching.",
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
            "label": f"F5 Bot Defense steering for {plan['vs']}",
            "remark": notes[0][:64],
            tenant: {"class": "Tenant", "Shared": app},
        },
        "_notes": notes,
    }
    return json.dumps(decl, indent=2)
