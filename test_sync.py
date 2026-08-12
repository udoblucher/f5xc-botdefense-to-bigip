#!/usr/bin/env python3
"""test_sync.py -- the sync diff engine, with no BIG-IP and no network.

The parser cases are verbatim `tmsh list ... one-line` output captured from a
17.5.1 box, not invented: the whole point of that format is that it is stable,
and a fixture someone wrote by hand cannot prove it was read correctly.

    python3 test_sync.py
"""

from __future__ import annotations

import sys

import sync
from render import names_for

FAILURES = []


def check(label, got, want):
    if got != want:
        FAILURES.append(f"{label}\n     got: {got!r}\n    want: {want!r}")


# ---------------------------------------------------------------------------
# parse_one_line -- real output from a lab BIG-IP
# ---------------------------------------------------------------------------
REAL = {
    "ip type": (
        "ltm data-group internal private_net { records { 10.0.0.0/8 { } "
        "172.16.0.0/12 { } 192.168.0.0/16 { } } type ip }",
        {"10.0.0.0/8": "", "172.16.0.0/12": "", "192.168.0.0/16": ""},
    ),
    "string type": (
        "ltm data-group internal images { records { .bmp { } .gif { } "
        ".jpg { } } type string }",
        {".bmp": "", ".gif": "", ".jpg": ""},
    ),
    "with data values": (
        "ltm data-group internal bot-entrypoint { records { /login { data GET } "
        "/register { data GET } } type string }",
        {"/login": "GET", "/register": "GET"},
    ),
    "paths, no values": (
        "ltm data-group internal bot-endpoints { records { /login { } "
        "/register { } } type string }",
        {"/login": "", "/register": ""},
    ),
}
for label, (text, want) in REAL.items():
    check(f"parse_one_line: {label}", sync.parse_one_line(text), want)

# Shapes the real box will produce that the captured set happens not to cover.
check("parse_one_line: no records block",
      sync.parse_one_line("ltm data-group internal empty { type string }"), {})
check("parse_one_line: quoted multi-word value",
      sync.parse_one_line('ltm data-group internal x { records { /a '
                          '{ data "GET POST" } } type string }'),
      {"/a": "GET POST"})
check("parse_one_line: quoted key with a space",
      sync.parse_one_line('ltm data-group internal x { records { "/a b" { } } '
                          'type string }'),
      {"/a b": ""})
check("parse_one_line: empty input", sync.parse_one_line(""), {})
check("parse_one_line: garbage", sync.parse_one_line("not a data group"), {})

# Name extraction from `list <glob> one-line`, also real output. tmsh reports
# bare names even when the glob was partition-qualified.
check("_DG_LINE: names from a glob listing",
      sync._DG_LINE.findall(
          "ltm data-group internal bot-endpoints { records { /login { } } "
          "type string }\nltm data-group internal bot-entrypoint { records "
          "{ /login { data GET } } type string }\nltm data-group internal "
          "bot-js { records { /common.js { } } type string }\n"),
      ["bot-endpoints", "bot-entrypoint", "bot-js"])
check("_DG_LINE: no match on an error body",
      sync._DG_LINE.findall(
          "01020036:3: The requested value list (zzz-*) was not found."), [])

# ---------------------------------------------------------------------------
# desired_state -- must agree with what build produces
# ---------------------------------------------------------------------------
INPUTS = {
    "xc": {"tenant": "acme", "namespace": "bot", "infra": "my-bot-infra",
           "policy": "shop-bot", "policy_version_deployed": 7,
           "policy_version_latest": 7},
    "bot_service": {"host": "svc.example.net", "port": 443,
                    "egress_ips": ["203.0.113.10", "203.0.113.11/32"]},
    "js": {"script_src": "/common.js?single", "match_path": "/common.js"},
    "endpoints": [
        {"name": "login", "methods": ["POST"], "get_document": False,
         "combine": "and",
         "matches": [{"op": "equals", "value": "/rest/user/login",
                      "nocase": True, "negate": False}]},
        {"name": "search", "methods": ["GET"], "get_document": False,
         "combine": "and",
         "matches": [{"op": "ends-with", "value": "/rest/products/search",
                      "nocase": True, "negate": False}]},
    ],
    "unsupported_endpoints": [],
    "mobile_endpoint_count": 0,
}
N = names_for("bot-defense")
want, meta = sync.desired_state(INPUTS, "bot-defense")
check("desired_state: data group set",
      sorted(want),
      ["bot-defense-egress", "bot-defense-endpoints-get-endswith-ci",
       "bot-defense-endpoints-post-equals-ci"])
check("desired_state: records lowercased for nocase buckets",
      want["bot-defense-endpoints-post-equals-ci"], {"/rest/user/login": ""})
check("desired_state: bare egress IP gets /32",
      sorted(want["bot-defense-egress"]),
      ["203.0.113.10/32", "203.0.113.11/32"])
check("desired_state: entrypoint data group is never included",
      N["dg_entry"] in want, False)
check("desired_state: js data group is never included",
      N["dg_js"] in want, False)

merged, _ = sync.desired_state(INPUTS, "bot-defense", "contains")
check("desired_state: --merge-ops collapses to one dg per method",
      sorted(k for k in merged if "endpoints" in k),
      ["bot-defense-endpoints-get", "bot-defense-endpoints-post"])


def delta_for(live, new=INPUTS, old=INPUTS, prefix="bot-defense", merge=""):
    w, m = sync.desired_state(new, prefix, merge)
    return sync.diff(w, live, m, old, new), w, m


BASE_LIVE = {
    "bot-defense-egress": {"203.0.113.10/32": "", "203.0.113.11/32": ""},
    "bot-defense-endpoints-post-equals-ci": {"/rest/user/login": ""},
    "bot-defense-endpoints-get-endswith-ci": {"/rest/products/search": ""},
}

# --- row: nothing changed
d, _, _ = delta_for(dict(BASE_LIVE))
check("in sync: no records", d.records, {})
check("in sync: no review", d.review, [])
check("in sync: exit 0", d.exit_code(), sync.EXIT_NO_CHANGE)

# --- row: record added to an existing bucket -> staged
live = {k: dict(v) for k, v in BASE_LIVE.items()}
del live["bot-defense-endpoints-post-equals-ci"]["/rest/user/login"]
live["bot-defense-endpoints-post-equals-ci"]["/old/path"] = ""
d, _, _ = delta_for(live)
check("record add+delete: staged",
      d.records["bot-defense-endpoints-post-equals-ci"],
      {"add": ["/rest/user/login"], "delete": ["/old/path"]})
check("record add+delete: no review", d.review, [])
check("record add+delete: exit 10", d.exit_code(), sync.EXIT_STAGED)

# --- row: egress change -> staged
live = {k: dict(v) for k, v in BASE_LIVE.items()}
live["bot-defense-egress"] = {"203.0.113.10/32": ""}
d, _, _ = delta_for(live)
check("egress add: staged", d.records["bot-defense-egress"],
      {"add": ["203.0.113.11/32"], "delete": []})

# --- row: new bucket (absent data group) -> review, never staged
new = json_copy = {**INPUTS, "endpoints": INPUTS["endpoints"] + [
    {"name": "admin", "methods": ["DELETE"], "get_document": False,
     "combine": "and",
     "matches": [{"op": "starts-with", "value": "/admin/", "nocase": False,
                  "negate": False}]}]}
live = {**{k: dict(v) for k, v in BASE_LIVE.items()},
        "bot-defense-endpoints-delete-startswith": None}
d, _, _ = delta_for(live, new=new)
check("new bucket: one review item", [r["kind"] for r in d.review],
      ["new-bucket"])
check("new bucket: nothing staged", d.records, {})
check("new bucket: exit 20", d.exit_code(), sync.EXIT_REVIEW)
check("new bucket: names the policy",
      "bot-defense-policy" in d.review[0]["why"], True)

# --- row: bucket XC no longer wants -> review
live = {**{k: dict(v) for k, v in BASE_LIVE.items()},
        "bot-defense-endpoints-get-equals": {"/legacy": ""}}
d, _, _ = delta_for(live)
check("dead bucket: review", [r["kind"] for r in d.review], ["dead-bucket"])
check("dead bucket: nothing staged", d.records, {})

# --- row: js change -> review, and the js dg is still never staged
new_js = {**INPUTS, "js": {"script_src": "/other.js?single",
                           "match_path": "/other.js"}}
d, _, _ = delta_for(dict(BASE_LIVE), new=new_js)
check("js change: two review items (src and path)",
      sorted(r["kind"] for r in d.review), ["js-changed", "js-changed"])
check("js change: nothing staged", d.records, {})

# --- row: service host change -> review
new_svc = {**INPUTS, "bot_service": {**INPUTS["bot_service"],
                                     "host": "other.example.net"}}
d, _, _ = delta_for(dict(BASE_LIVE), new=new_svc)
check("service change: review", [r["kind"] for r in d.review],
      ["service-changed"])
check("service change: names the pool",
      "bot-defense-pool" in d.review[0]["why"], True)

# --- row: GET_DOCUMENT set changed -> advisory only, entrypoint dg untouched
new_doc = {**INPUTS, "endpoints": [
    {**INPUTS["endpoints"][0], "get_document": True}, INPUTS["endpoints"][1]]}
d, _, _ = delta_for(dict(BASE_LIVE), new=new_doc)
check("get_document change: no review", d.review, [])
check("get_document change: no records", d.records, {})
check("get_document change: advisory mentions the hand-maintained dg",
      any("maintained by hand" in a for a in d.advisories), True)

# --- row: unsupported endpoint appears -> advisory
new_un = {**INPUTS, "unsupported_endpoints": [
    {"name": "weird", "reason": "path_and is not expressible"}]}
d, _, _ = delta_for(dict(BASE_LIVE), new=new_un)
check("unsupported endpoint: advisory",
      any("not protected" in a for a in d.advisories), True)
check("unsupported endpoint: exit 0", d.exit_code(), sync.EXIT_NO_CHANGE)

# ---------------------------------------------------------------------------
# fingerprint -- the staleness guard
# ---------------------------------------------------------------------------
names = sorted(BASE_LIVE)
f1 = sync.fingerprint(BASE_LIVE, names)
check("fingerprint: stable across calls", sync.fingerprint(BASE_LIVE, names), f1)
moved = {k: dict(v) for k, v in BASE_LIVE.items()}
moved["bot-defense-endpoints-post-equals-ci"]["/snuck-in"] = ""
check("fingerprint: changes when a record is added",
      sync.fingerprint(moved, names) != f1, True)
absent = {**{k: dict(v) for k, v in BASE_LIVE.items()},
          "bot-defense-egress": None}
check("fingerprint: absent differs from empty",
      sync.fingerprint(absent, names) !=
      sync.fingerprint({**absent, "bot-defense-egress": {}}, names), True)

# ---------------------------------------------------------------------------
# render_sync_script -- only ever record edits, always saves
# ---------------------------------------------------------------------------
live = {k: dict(v) for k, v in BASE_LIVE.items()}
del live["bot-defense-endpoints-post-equals-ci"]["/rest/user/login"]
live["bot-defense-endpoints-post-equals-ci"]["/old"] = ""
d, w, m = delta_for(live)
script = sync.render_sync_script(d, "bot-defense", "Common", "the diff")
check("script: adds the new record",
      "records add { /rest/user/login { } }" in script, True)
check("script: deletes the stale record",
      "records delete { /old { } }" in script, True)
check("script: saves the config", "save sys config" in script, True)
check("script: carries the fingerprint",
      f"state-fingerprint: {d.fingerprint}" in script, True)
for forbidden in ("replace-all-with", "modify ltm virtual", "ltm policy",
                  "create ltm", "delete ltm", "load sys config"):
    check(f"script: never contains {forbidden!r}", forbidden in script, False)

# A partition build must qualify every name, or tmsh resolves it in /Common.
d2, _, _ = delta_for(live)
part_script = sync.render_sync_script(d2, "bot-defense", "prod")
check("script: qualifies names in a partition",
      "/prod/bot-defense-endpoints-post-equals-ci" in part_script, True)

# The review artifact must refuse to run even if someone bashes it.
d3, _, _ = delta_for({**{k: dict(v) for k, v in BASE_LIVE.items()},
                      "bot-defense-endpoints-delete-startswith": None}, new=new)
review = sync.render_review_script(d3, "bot-defense")
check("review script: exits before doing anything",
      review.index("exit 1") < len(review), True)
check("review script: the only live line is the refusal to run",
      [l for l in review.splitlines()
       if l.strip() and not l.startswith("#")
       and not l.startswith("exit 1")], [])

# ---------------------------------------------------------------------------
# format_delta / summary_line
# ---------------------------------------------------------------------------
report = sync.format_delta(d, "bot-defense", "Common", "/var/tmp/x.sh")
check("report: shows the add with a +", "+ /rest/user/login" in report, True)
check("report: shows the delete with a -", "- /old" in report, True)
check("report: tells you how to apply", "sync --apply /var/tmp/x.sh" in report,
      True)
check("summary: one line", "\n" in sync.summary_line(d), False)
check("summary: counts the changes",
      "2 record change(s) staged" in sync.summary_line(d), True)
check("summary: counts review items",
      "1 needing review" in sync.summary_line(d3), True)

# ---------------------------------------------------------------------------
if FAILURES:
    print(f"{len(FAILURES)} FAILED\n")
    for f in FAILURES:
        print(f"  - {f}\n")
    sys.exit(1)
print("all sync tests passed")
