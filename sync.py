#!/usr/bin/env python3
"""sync.py -- has the XC policy moved since we deployed it, and what changed?

The generated config is a snapshot. When someone adds a protected endpoint to
the Bot Endpoint Policy in XC, the BIG-IP goes on steering the old set and the
new endpoint reaches the application uninspected, silently. This finds that.

    desired_state()  fresh XC inputs        -> {data-group: {record: value}}
    read live        the box, via tmsh/REST  -> {data-group: {record: value}}
    diff()           the two                -> Delta, classified
    render_sync_script()   Delta            -> tmsh commands for the safe part

The live data groups are the baseline, not a recorded snapshot of what we think
we deployed. A record someone edited by hand then shows up as drift to be
reviewed rather than being assumed away.

WHY THE DIFF IS CLASSIFIED
--------------------------
render._endpoint_buckets() groups endpoints by (method, operator, case,
negation) and each bucket becomes one data group AND one LTM policy rule. So an
endpoint whose tuple already has a bucket is a record added to an existing data
group -- reversible, touches no traffic-path object. An endpoint with a NEW
tuple needs a new data group and a new rule inside the live policy, and
render_tmsh applies policies with `load sys config merge`, which rewrites the
whole published object at once. Those two things are not the same risk, so they
do not travel together: only the first is ever staged for apply.

Python 3.7+ standard library only -- this runs on the BIG-IP itself.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess

from render import DEFAULT_PARTITION, _endpoint_buckets, names_for, qualified

# Exit codes, also the notification: cron mails stdout, and a caller can branch
# on these without parsing anything.
EXIT_NO_CHANGE = 0
EXIT_STAGED = 10
EXIT_REVIEW = 20

# tmsh's "not found" for a data group. Distinguishing it from a real failure is
# what tells us a bucket does not exist on the box yet, as opposed to the box
# being unreachable -- treating those alike would either invent spurious
# "new bucket" findings or hide real ones.
TMSH_NOT_FOUND = "01020036"


# ---------------------------------------------------------------------------
# Reading what is on the box
# ---------------------------------------------------------------------------
# `tmsh list ... one-line` output, verified on 17.5.1:
#   ltm data-group internal images { records { .bmp { } .gif { } } type string }
#   ltm data-group internal bot-entrypoint { records { /login { data GET } } ... }
# A data group with no records omits the `records` block entirely.
_RECORDS_BLOCK = re.compile(r"\brecords\s*\{")

# `list ltm data-group internal <glob> one-line` reports each object as
#   ltm data-group internal <bare name> { ... }
# -- bare even when the glob was partition-qualified (verified on 17.5.1).
_DG_LINE = re.compile(r"^ltm data-group internal (\S+)", re.M)


def parse_one_line(text: str) -> dict[str, str]:
    """Records from one `tmsh list ltm data-group internal <n> one-line` output.

    Returns {key: value}, value "" for a record that carries no data. Parsed by
    walking braces rather than with one regex: record keys are arbitrary paths
    and values may be quoted and contain spaces ("GET POST"), which a single
    pattern gets wrong in both directions.

    An empty or unparseable body gives {} -- an existing data group with no
    records and an absent one are told apart by the caller, which knows whether
    tmsh said 01020036.
    """
    m = _RECORDS_BLOCK.search(text or "")
    if not m:
        return {}
    i, depth, end = m.end(), 1, -1
    while i < len(text):                     # find the matching close brace
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                end = i
                break
        i += 1
    if end < 0:
        return {}
    body, out, i = text[m.end():end], {}, 0

    def _skip_space(j: int) -> int:
        while j < len(body) and body[j].isspace():
            j += 1
        return j

    while True:
        i = _skip_space(i)
        if i >= len(body):
            break
        # Key: up to the next whitespace or brace. Quoted if it contains either.
        if body[i] == '"':
            j = i + 1
            while j < len(body) and (body[j] != '"' or body[j - 1] == "\\"):
                j += 1
            key, i = body[i + 1:j], j + 1
        else:
            j = i
            while j < len(body) and not body[j].isspace() and body[j] != "{":
                j += 1
            key, i = body[i:j], j
        i = _skip_space(i)
        if i >= len(body) or body[i] != "{":
            # Malformed; record the key with no value rather than losing it.
            if key:
                out[key] = ""
            continue
        # Value block: `{ }` or `{ data VALUE }`, VALUE possibly quoted.
        depth, j = 1, i + 1
        while j < len(body) and depth:
            if body[j] == "{":
                depth += 1
            elif body[j] == "}":
                depth -= 1
            j += 1
        inner = body[i + 1:j - 1].strip()
        value = ""
        if inner.startswith("data"):
            raw = inner[4:].strip()
            value = raw[1:-1] if len(raw) > 1 and raw[0] == raw[-1] == '"' else raw
        if key:
            out[key] = value
        i = j
    return out


class LocalTransport:
    """Read and write data groups with tmsh, on the box itself.

    Used by the cron path, where requiring iControl REST credentials to talk to
    the local device would mean storing a BIG-IP password next to the XC token
    for no gain.
    """

    label = "local tmsh"

    def __init__(self, partition: str = DEFAULT_PARTITION):
        self.partition = partition

    def read_data_groups(self, names) -> dict[str, dict[str, str] | None]:
        """{name: records} per name, or None where the data group is absent."""
        out = {}
        for name in names:
            q = qualified(self.partition, name)
            proc = subprocess.run(
                ["tmsh", "-c", f"list ltm data-group internal {q} one-line"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            text = proc.stdout.decode("utf-8", "replace")
            if proc.returncode != 0:
                if TMSH_NOT_FOUND in text:
                    out[name] = None
                    continue
                raise RuntimeError(
                    f"could not read data group {name}: {' '.join(text.split())}")
            out[name] = parse_one_line(text)
        return out

    def list_data_groups(self, prefix: str) -> list[str]:
        """Bare names of the data groups matching `<prefix>*` in the partition.

        A glob that matches nothing exits 1 with 01020036, the same way a named
        object that does not exist does -- so "none" and "not deployed" arrive
        as the same clean answer rather than as an error.
        """
        glob = qualified(self.partition, prefix) + "*"
        proc = subprocess.run(
            ["tmsh", "-c", f"list ltm data-group internal {glob} one-line"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        text = proc.stdout.decode("utf-8", "replace")
        if proc.returncode != 0:
            if TMSH_NOT_FOUND in text:
                return []
            raise RuntimeError(
                f"could not list data groups: {' '.join(text.split())}")
        return sorted(_DG_LINE.findall(text))

    def run_script(self, text: str, remote_name: str = "") -> str:
        proc = subprocess.run(["bash", "-s"], input=text.encode(),
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        result = proc.stdout.decode("utf-8", "replace")
        if proc.returncode != 0:
            raise RuntimeError(f"the sync script failed:\n{result}")
        return result


class RestTransport:
    """Same two operations against a remote BIG-IP over iControl REST."""

    def __init__(self, bigip, partition: str = DEFAULT_PARTITION):
        self.bigip = bigip
        self.partition = partition
        self.label = f"iControl REST on {bigip.host}"

    def read_data_groups(self, names) -> dict[str, dict[str, str] | None]:
        return self.bigip.data_groups(names, self.partition)

    def list_data_groups(self, prefix: str) -> list[str]:
        return [n for n in self.bigip.data_group_names(self.partition)
                if n.startswith(prefix)]

    def run_script(self, text: str, remote_name: str = "xcbot-sync.sh") -> str:
        # Raised rather than returned, to match LocalTransport above: a sync
        # script that stopped partway through has written some records and not
        # others, and the caller has to hear about that as a failure.
        out, rc = self.bigip.deploy_tmsh(text, remote_name)
        if rc != 0:
            raise RuntimeError(f"the sync script failed (exit {rc}):\n{out}")
        return out


# ---------------------------------------------------------------------------
# Desired state
# ---------------------------------------------------------------------------
def desired_state(inputs: dict, prefix: str, merge_op: str = "",
                  partition: str = DEFAULT_PARTITION) -> tuple[dict, dict]:
    """({data-group: {record: value}}, meta) that `build` would produce now.

    Deliberately routed through _endpoint_buckets() and names_for() rather than
    recomputed: if the bucket keying or the naming ever changes, the diff has to
    change with it or it starts reporting differences that are really just this
    module disagreeing with the generator.

    Only the data groups sync is allowed to reason about are returned. The
    entrypoint data group is excluded on purpose -- XC does not record which
    pages need the script, so nothing here can regenerate it.
    """
    n = names_for(prefix)
    buckets, warnings = _endpoint_buckets(inputs, n["dg_ep_prefix"], merge_op)

    want = {}
    for b in buckets:
        want[b["dg"]] = {v: "" for v in b["values"]}

    egress = [ip if "/" in ip else f"{ip}/32"
              for ip in (inputs.get("bot_service", {}).get("egress_ips") or [])]
    if egress:
        want[n["dg_egress"]] = {ip: "" for ip in egress}

    meta = {
        "names": n,
        "partition": partition,
        "buckets": {b["dg"]: b for b in buckets},
        "warnings": warnings,
        "ep_prefix": n["dg_ep_prefix"],
    }
    return want, meta


# ---------------------------------------------------------------------------
# The diff
# ---------------------------------------------------------------------------
class Delta:
    """What changed, split by what it is safe to do about it.

    `records` is the staged part: data groups that exist on both sides, where
    the change is only which keys they hold. `review` is everything that would
    need an object created, deleted, or rewritten -- reported with the commands
    it would take, never staged for apply. `advisories` are things worth a human
    knowing that imply no BIG-IP change at all.
    """

    def __init__(self):
        self.records: dict[str, dict[str, list[str]]] = {}
        self.review: list[dict] = []
        self.advisories: list[str] = []
        self.versions: dict[str, str] = {}
        self.fingerprint: str = ""
        self.missing_prefix: bool = False

    @property
    def has_records(self) -> bool:
        return bool(self.records)

    @property
    def has_review(self) -> bool:
        return bool(self.review)

    def exit_code(self) -> int:
        if self.has_review:
            return EXIT_REVIEW
        return EXIT_STAGED if self.has_records else EXIT_NO_CHANGE

    def touched(self) -> list[str]:
        return sorted(self.records)


def fingerprint(live: dict, names) -> str:
    """Stable hash of the live records of `names`, for the staleness guard.

    Applying a diff computed against a box that has since changed is the one way
    a reviewed artifact can still do something the reviewer did not see, so the
    state it was computed against is recorded and rechecked at apply time.
    """
    h = hashlib.sha256()
    for name in sorted(names):
        recs = live.get(name)
        h.update(f"\x00{name}\x00".encode())
        if recs is None:
            h.update(b"<absent>")
            continue
        for k in sorted(recs):
            h.update(f"{k}={recs[k]}\x01".encode())
    return h.hexdigest()[:16]


def diff(want: dict, live: dict, meta: dict, old_inputs: dict,
         new_inputs: dict) -> Delta:
    """Classify every difference. See the module docstring for why.

    `live` maps name -> records, or name -> None for a data group that is not on
    the box. `old_inputs` is the last fetched inputs file, used only for the
    non-data-group comparisons and the version line.
    """
    d = Delta()
    part = meta["partition"]
    old_xc = (old_inputs or {}).get("xc", {})
    new_xc = (new_inputs or {}).get("xc", {})
    d.versions = {
        "policy": new_xc.get("policy", ""),
        "was": str(old_xc.get("policy_version_deployed", "?")),
        "now": str(new_xc.get("policy_version_deployed", "?")),
        "latest": str(new_xc.get("policy_version_latest", "?")),
    }

    # A bucket XC wants that has no data group on the box needs the data group
    # AND a policy rule, so it is review, not a record edit.
    for name in sorted(want):
        recs = live.get(name)
        if recs is None:
            b = meta["buckets"].get(name)
            if b:
                d.review.append({
                    "kind": "new-bucket",
                    "what": f"{name}: no such data group on the box",
                    "why": f"{b['method']} {'NOT ' if b['negate'] else ''}"
                           f"{b['op']}{' (nocase)' if b['nocase'] else ''} is a "
                           f"combination nothing was built for, so it needs a "
                           f"new data group AND a new rule in "
                           f"{qualified(part, meta['names']['policy'])}.",
                    "values": sorted(want[name]),
                    "sources": b.get("sources") or [],
                })
            else:
                d.review.append({
                    "kind": "missing-dg",
                    "what": f"{name}: no such data group on the box",
                    "why": "Expected by the build but absent. Was it deleted, "
                           "or is --prefix wrong?",
                    "values": sorted(want[name]),
                    "sources": [],
                })
            continue
        added = sorted(set(want[name]) - set(recs))
        removed = sorted(set(recs) - set(want[name]))
        if added or removed:
            d.records[name] = {"add": added, "delete": removed}

    # A data group on the box under our endpoint prefix that XC no longer wants
    # at all: its policy rule should go too, which is a policy rewrite.
    for name in sorted(live):
        if name in want or live.get(name) is None:
            continue
        if name.startswith(meta["ep_prefix"]):
            d.review.append({
                "kind": "dead-bucket",
                "what": f"{name}: XC no longer has any endpoint in this bucket",
                "why": f"Removing it means also removing its rule from "
                       f"{qualified(part, meta['names']['policy'])}. Until then "
                       f"it keeps steering {len(live[name])} path(s) to Bot "
                       f"Defense, which is inspection nothing asked for rather "
                       f"than a gap.",
                "values": sorted(live[name]),
                "sources": [],
            })

    # Non-data-group drift. Reported, never applied: each of these lands on an
    # object the record-level edits do not touch.
    old_js, new_js = (old_inputs or {}).get("js", {}), new_inputs.get("js", {})
    for field, obj in (("script_src", "the injected <script> tag (HTML rule)"),
                       ("match_path", "the JS data group and the HTML rule")):
        if old_js and old_js.get(field) != new_js.get(field):
            d.review.append({
                "kind": "js-changed",
                "what": f"js.{field}: {old_js.get(field)!r} -> "
                        f"{new_js.get(field)!r}",
                "why": f"Changes {obj}. The data group and the rule carry the "
                       f"same path and have to move together, so this is a "
                       f"rebuild, not a record edit.",
                "values": [], "sources": [],
            })

    old_svc = (old_inputs or {}).get("bot_service", {})
    new_svc = new_inputs.get("bot_service", {})
    for field in ("host", "port"):
        if old_svc and str(old_svc.get(field)) != str(new_svc.get(field)):
            d.review.append({
                "kind": "service-changed",
                "what": f"bot_service.{field}: {old_svc.get(field)} -> "
                        f"{new_svc.get(field)}",
                "why": f"That is the member of "
                       f"{qualified(part, meta['names']['pool'])}. Change the "
                       f"pool member and re-check the monitor.",
                "values": [], "sources": [],
            })

    # Advisories: no BIG-IP object changes, but a person should know.
    old_doc = {ep.get("name") for ep in (old_inputs or {}).get("endpoints", [])
               if ep.get("get_document")}
    new_doc = {ep.get("name") for ep in new_inputs.get("endpoints", [])
               if ep.get("get_document")}
    if old_inputs and old_doc != new_doc:
        gained, lost = sorted(new_doc - old_doc), sorted(old_doc - new_doc)
        d.advisories.append(
            "XC's GET_DOCUMENT endpoints changed"
            + (f" (+{', '.join(g or '(unnamed)' for g in gained)})" if gained else "")
            + (f" (-{', '.join(l or '(unnamed)' for l in lost)})" if lost else "")
            + f". {qualified(part, meta['names']['dg_entry'])} is maintained by "
              f"hand and was NOT touched -- check whether the injection list "
              f"needs the same change.")

    old_un = {u.get("name") for u in (old_inputs or {}).get("unsupported_endpoints", [])}
    for u in new_inputs.get("unsupported_endpoints", []):
        if u.get("name") not in old_un:
            d.advisories.append(
                f"XC endpoint '{u.get('name')}' cannot be expressed as an LTM "
                f"policy rule ({u.get('reason')}) -- it is not protected by this "
                f"config and no data group covers it.")
    if new_inputs.get("mobile_endpoint_count") and not (old_inputs or {}).get(
            "mobile_endpoint_count"):
        d.advisories.append(
            f"{new_inputs['mobile_endpoint_count']} mobile endpoint(s) now in the "
            f"policy. Those need the Bot Defense SDK, not this config.")

    d.advisories.extend(meta.get("warnings") or [])
    d.fingerprint = fingerprint(live, set(want) | set(live))
    return d


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def format_delta(d: Delta, prefix: str, partition: str = DEFAULT_PARTITION,
                 staged_path: str = "", review_path: str = "") -> str:
    """The diff, as the operator reads it. Same text to stdout, log and script."""
    v = d.versions
    L = []
    if v.get("was") == v.get("now"):
        L.append(f"XC policy '{v.get('policy')}' v{v.get('now')} -- unchanged "
                 f"version")
    else:
        L.append(f"XC policy '{v.get('policy')}' v{v.get('was')} -> v{v.get('now')}")
    if v.get("latest") not in ("?", v.get("now")):
        L.append(f"  (XC's latest is v{v['latest']}; the infra runs v{v['now']})")
    L.append("")

    if d.has_records:
        total = sum(len(c["add"]) + len(c["delete"]) for c in d.records.values())
        L.append(f"CHANGES TO APPLY -- data-group records only ({total})")
        for name in sorted(d.records):
            L.append(f"  {qualified(partition, name)}")
            for k in d.records[name]["add"]:
                L.append(f"    + {k}")
            for k in d.records[name]["delete"]:
                L.append(f"    - {k}")
        L.append("")

    if d.has_review:
        L.append(f"NEEDS REVIEW -- not staged, not applied ({len(d.review)})")
        for r in d.review:
            L.append(f"  ! {r['what']}")
            L.append(f"    {r['why']}")
            for s in (r.get("sources") or [])[:8]:
                L.append(f"      from XC: {s}")
            if not r.get("sources"):
                for val in (r.get("values") or [])[:8]:
                    L.append(f"      {val}")
        L.append("")

    if d.advisories:
        L.append("FOR INFORMATION")
        for a in d.advisories:
            L.append(f"  - {a}")
        L.append("")

    if not (d.has_records or d.has_review):
        L.append("No differences. The data groups on the box match the XC policy.")
        L.append("")

    if staged_path:
        L.append(f"Staged : {staged_path}")
        L.append(f"Apply  : xcbot.py sync --apply {staged_path}")
        L.append(f"         (shows this diff again and asks before writing)")
    if review_path:
        L.append(f"Review : {review_path}  -- read it; --apply will not run it")
    return "\n".join(L)


def summary_line(d: Delta) -> str:
    """One line for syslog. Front-loaded with the part that needs action."""
    v = d.versions
    bits = []
    if d.has_records:
        n = sum(len(c["add"]) + len(c["delete"]) for c in d.records.values())
        bits.append(f"{n} record change(s) staged")
    if d.has_review:
        bits.append(f"{len(d.review)} needing review")
    if not bits:
        bits.append("no changes")
    return (f"policy={v.get('policy')} v{v.get('was')}->v{v.get('now')}: "
            + ", ".join(bits))


# ---------------------------------------------------------------------------
# The staged artifact
# ---------------------------------------------------------------------------
def _tmsh_keys(keys) -> str:
    """Record keys as a tmsh brace list. Quoted only where they must be."""
    out = []
    for k in keys:
        safe = k.replace("\\", "\\\\").replace('"', '\\"').replace("?", "\\?")
        out.append(f'"{safe}" {{ }}' if (safe != k or re.search(r"[\s{}]", k))
                   else f"{k} {{ }}")
    return " ".join(out)


def render_sync_script(d: Delta, prefix: str, partition: str = DEFAULT_PARTITION,
                       diff_text: str = "") -> str:
    """The apply script: targeted record edits, nothing else.

    `records add` / `records delete` of exactly the keys in the diff, not
    `replace-all-with`: a record someone added on purpose is then left alone and
    reported as drift next run, instead of being silently reverted by a job.
    """
    L = ["#!/bin/bash",
         "# Generated by xcbot.py sync --check. Applies ONLY the data-group",
         "# record changes below. Review it, then:",
         "#     xcbot.py sync --apply <this file>",
         f"# state-fingerprint: {d.fingerprint}",
         "#"]
    for line in (diff_text or "").splitlines():
        L.append(f"# {line}".rstrip())
    L += ["", "set -e", ""]
    for name in sorted(d.records):
        q = qualified(partition, name)
        change = d.records[name]
        if change["add"]:
            L.append(f'tmsh -c \'modify ltm data-group internal {q} records add '
                     f'{{ {_tmsh_keys(change["add"])} }}\'')
        if change["delete"]:
            L.append(f'tmsh -c \'modify ltm data-group internal {q} records '
                     f'delete {{ {_tmsh_keys(change["delete"])} }}\'')
    # Data groups live in the running config until this is run; without it the
    # change is lost on reboot.
    L += ["", "tmsh -c 'save sys config'",
          f'echo "sync applied: {len(d.records)} data group(s)"']
    return "\n".join(L) + "\n"


def render_review_script(d: Delta, prefix: str,
                         partition: str = DEFAULT_PARTITION) -> str:
    """What the review items would take, as commands -- to read, not to run.

    Not runnable by --apply on purpose. Every item here rewrites or creates a
    traffic-path object, and the honest remedy for most of them is to re-run
    fetch and build and read the attach step, which is what the notes say.
    """
    n = names_for(prefix)
    L = ["#!/bin/bash",
         "# NOT RUNNABLE BY 'sync --apply'. Read it.",
         "#",
         "# Each item below needs an object created, deleted or rewritten, so it",
         "# is a config change to review rather than a record edit to approve.",
         f"# The LTM policy {qualified(partition, n['policy'])} is applied with",
         "# 'load sys config merge', which rewrites the whole published policy",
         "# in one operation -- which is why none of this is staged for apply.",
         "#",
         "# For anything marked new-bucket or dead-bucket the supported route is:",
         "#     xcbot.py fetch --tenant <t> --namespace <ns> --infra <i>",
         "#     xcbot.py build --vs <vs> --prefix " + prefix,
         "#   then read the step marked 'affects live traffic' before running it.",
         "",
         "exit 1   # refuse to run by accident",
         ""]
    for r in d.review:
        L.append(f"# --- {r['kind']}: {r['what']}")
        for line in r["why"].split(". "):
            if line.strip():
                L.append(f"#     {line.strip().rstrip('.')}.")
        if r["kind"] == "new-bucket":
            L.append(f"#   tmsh -c 'create ltm data-group internal "
                     f"{qualified(partition, r['what'].split(':')[0])} type "
                     f"string records add {{ {_tmsh_keys(r['values'])} }}'")
            L.append(f"#   ...and a matching rule in "
                     f"{qualified(partition, n['policy'])}.")
        elif r["kind"] == "dead-bucket":
            L.append(f"#   tmsh -c 'delete ltm data-group internal "
                     f"{qualified(partition, r['what'].split(':')[0])}'")
            L.append(f"#   ...after removing its rule from "
                     f"{qualified(partition, n['policy'])}.")
        L.append("")
    return "\n".join(L) + "\n"


def sidecar(d: Delta, prefix: str, partition: str, want: dict,
            live: dict) -> str:
    """The JSON written next to the staged script: what --apply rechecks."""
    return json.dumps({
        "schema": "xcbot-sync/1",
        "prefix": prefix,
        "partition": partition,
        "fingerprint": d.fingerprint,
        "versions": d.versions,
        "records": d.records,
        "review": [{"kind": r["kind"], "what": r["what"]} for r in d.review],
        "advisories": d.advisories,
        "checked": sorted(set(want) | set(live)),
    }, indent=2) + "\n"
