#!/usr/bin/env python3
"""xcbot.py -- XC Bot Defense -> BIG-IP configuration artifacts.

Two commands, in the order you use them:

  fetch    Read the Bot Infrastructure and Bot Endpoint Policy out of F5
           Distributed Cloud and save them, normalized, to a local JSON file.
           This is the only step that talks to XC.

  build    Read that file, ask what it cannot know (which virtual server), and
           write the configuration artifacts:

             <vs>_botdefense_ui.md      click-by-click Configuration utility steps
             <vs>_botdefense.sh         numbered tmsh commands, runnable
             <vs>_botdefense_as3.json   AS3 declaration
             <irule>.tcl                the iRule body on its own

           Pick a subset with --ui / --tmsh / --as3; the default is all of them.

  deploy   Optional. Push an artifact that was already generated and reviewed.

  sync     Optional, and meant for cron. Re-read the policy from XC, compare it
           against the data groups as they actually are on the box, and report
           what moved. --check stages an apply script and writes no config;
           --apply runs that script after showing the diff and asking. Endpoint
           changes that would need a new LTM policy rule are reported, never
           staged -- see sync.py for why those are not the same risk.

Splitting fetch from build is the point: build never needs credentials or
network, so the same fetched file reproduces the same config, and the file can
be committed, diffed and reviewed as the record of what XC said.

Python 3.7+ standard library only.

  python3 xcbot.py fetch --tenant acme       # writes xc_api_token.txt, then
                                             # tells you to paste your token in
  python3 xcbot.py fetch --tenant acme --namespace bot-defense \\
                         --infra my-bot-infra
  python3 xcbot.py build --vs secureapp
"""

from __future__ import annotations

import argparse
import datetime
import getpass
import json
import os
import re
import subprocess
import sys
import urllib.error

import sync
import xc_api
from bigip_api import BigIP
from rest import HTTPError
from render import (build_plan, fingerprints, irule_selects_pool, render_as3,
                    render_tmsh, render_ui)

DEFAULT_INPUTS = "botdefense_inputs.json"

# The XC API token lives in a file by default. An environment variable is
# invisible once set -- there is nothing to look at to see whether it is right,
# it vanishes with the shell, and it lands in shell history. A file you can open,
# read, and correct. It is gitignored, and created with 0600 on first run.
DEFAULT_TOKEN_FILE = "xc_api_token.txt"
TOKEN_PLACEHOLDER = "PASTE_YOUR_XC_API_TOKEN_HERE"
TOKEN_TEMPLATE = f"""\
# F5 Distributed Cloud API token, read by xcbot.py fetch.
#
# Replace the last line of this file with your token. Get one in the XC console:
#   Administration >> Personal Management >> Credentials >> Add Credentials
#   Credential type: API Token
#
# Lines starting with # are ignored, so these notes can stay. Do not commit this
# file -- .gitignore already excludes it.
{TOKEN_PLACEHOLDER}
"""


# ---------------------------------------------------------------------------
# Prompting. Every question has a non-interactive equivalent, and --yes turns a
# missing answer into an error instead of a silent default.
# ---------------------------------------------------------------------------
class Asker:
    def __init__(self, interactive: bool):
        self.interactive = interactive and sys.stdin.isatty()

    def text(self, question: str, default: str = "", *, required: bool = True) -> str:
        if not self.interactive:
            if not default and required:
                raise SystemExit(
                    f"Need an answer for: {question}\n"
                    f"stdin is not a terminal (or --yes was given), so pass it "
                    f"as a command-line option instead.")
            return default
        suffix = f" [{default}]" if default else ""
        while True:
            try:
                answer = input(f"{question}{suffix}: ").strip() or default
            except (EOFError, KeyboardInterrupt):
                raise SystemExit("\nAborted.")
            if answer or not required:
                return answer
            print("  (required)", file=sys.stderr)

    def choose(self, question: str, options: list, default: str = "",
               labels: list | None = None) -> str:
        """Pick one of `options`. Falls through when there is only one."""
        if not options:
            return self.text(question, default)
        if len(options) == 1 and not default:
            default = options[0]
        if not self.interactive:
            if default in options:
                return default
            raise SystemExit(
                f"Need an answer for: {question}\nChoices: {', '.join(options)}")
        print(f"\n{question}", file=sys.stderr)
        for i, opt in enumerate(options, 1):
            label = f"  {i}. {labels[i - 1]}" if labels else f"  {i}. {opt}"
            print(label + ("   (default)" if opt == default else ""), file=sys.stderr)
        while True:
            try:
                raw = input("Choice: ").strip()
            except (EOFError, KeyboardInterrupt):
                raise SystemExit("\nAborted.")
            if not raw and default:
                return default
            if raw.isdigit() and 1 <= int(raw) <= len(options):
                return options[int(raw) - 1]
            if raw in options:
                return raw
            print("  (pick a number from the list)", file=sys.stderr)

    def confirm(self, question: str, default: bool = False) -> bool:
        if not self.interactive:
            return default
        suffix = " [Y/n]" if default else " [y/N]"
        try:
            raw = input(f"{question}{suffix} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            raise SystemExit("\nAborted.")
        return default if not raw else raw in ("y", "yes")


def _read_token_file(path: str) -> str:
    """First non-comment, non-empty line of a token file, or "" if unreadable.

    Comments are allowed so the file can explain itself -- it is the one file a
    person edits by hand, and a bare token in a bare file gives no hint what it
    is or where it came from.
    """
    try:
        with open(os.path.expanduser(path), encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    return line
    except OSError:
        return ""
    return ""


def _write_token_template(path: str) -> bool:
    """Create the token file with a placeholder. False if it already exists."""
    if os.path.exists(os.path.expanduser(path)):
        return False
    try:
        with open(os.path.expanduser(path), "w", encoding="utf-8") as fh:
            fh.write(TOKEN_TEMPLATE)
        # The file is about to hold a credential, so narrow it before it does.
        os.chmod(os.path.expanduser(path), 0o600)
    except OSError:
        return False
    return True


def _token(args) -> str:
    """The XC API token: --token-file, then the default file, then the env var.

    File before environment because the file is the one a person can find, see
    the state of, and edit again next month. The env var still wins nothing but
    still works, which is what CI wants.
    """
    if args.token_file:
        if not os.path.exists(os.path.expanduser(args.token_file)):
            raise SystemExit(f"No such file: {args.token_file}")
        token = _read_token_file(args.token_file)
        if not token or token == TOKEN_PLACEHOLDER:
            raise SystemExit(
                f"No token in {args.token_file}. Open it and put your XC API "
                f"token on a line of its own ('#' starts a comment).")
        return token

    token = _read_token_file(DEFAULT_TOKEN_FILE)
    if token and token != TOKEN_PLACEHOLDER:
        return token

    env = os.environ.get("F5XC_API_TOKEN", "").strip()
    if env:
        return env

    created = _write_token_template(DEFAULT_TOKEN_FILE)
    raise SystemExit(
        f"No XC API token yet.\n\n"
        f"  1. Open {DEFAULT_TOKEN_FILE}"
        + (" (just created for you)" if created else "") + "\n"
        f"  2. Replace the {TOKEN_PLACEHOLDER} line with your token\n"
        f"  3. Run the same command again\n\n"
        f"Get a token in the XC console under Administration >> Personal "
        f"Management >> Credentials >> Add Credentials, type 'API Token'.\n"
        f"Another file works too: --token-file PATH. So does the "
        f"F5XC_API_TOKEN environment variable.")


def _bigip(args, ask: Asker, required: bool = False) -> BigIP | None:
    """A BIG-IP client, or None when no host was given and none is required."""
    host = args.bigip
    if not host and required:
        host = ask.text("BIG-IP management address")
    if not host:
        return None
    password = os.environ.get("BIGIP_PASS", "")
    if not password:
        if not sys.stdin.isatty():
            raise SystemExit(
                "No BIG-IP password: set BIGIP_PASS, or run interactively.")
        password = getpass.getpass(f"Password for {args.bigip_user}@{host}: ")
    return BigIP(host, args.bigip_user, password, verify_tls=args.verify_bigip_tls)


# ---------------------------------------------------------------------------
# fetch
# ---------------------------------------------------------------------------
def cmd_fetch(args) -> int:
    ask = Asker(not args.yes)
    xc = xc_api.XC(args.tenant, _token(args), verify_tls=not args.no_verify_tls)

    namespace = args.namespace
    if not namespace:
        print("Listing namespaces ...", file=sys.stderr)
        namespace = ask.choose("Which XC namespace?", xc.list_namespaces())

    infra = args.infra
    if not infra:
        print(f"Listing Bot Infrastructures in '{namespace}' ...", file=sys.stderr)
        infras = xc.list_infras(namespace)
        if not infras:
            raise SystemExit(f"No Bot Infrastructures in namespace '{namespace}'.")
        infra = ask.choose("Which Bot Infrastructure?", infras)

    print(f"Fetching infra '{infra}' ...", file=sys.stderr)
    infra_obj = xc.get_infra(namespace, infra)

    meta = ((infra_obj.get("spec") or {}).get("bot_endpoint_policy_metadata")) or {}
    policy_name = meta.get("name") or ""
    if not policy_name:
        raise SystemExit(
            f"Infra '{infra}' references no Bot Endpoint Policy. Attach one in "
            f"the XC console first.")
    if args.policy and args.policy != policy_name:
        raise SystemExit(
            f"Infra '{infra}' runs policy '{policy_name}', not '{args.policy}'. "
            f"The infra decides which policy is live -- drop --policy, or point "
            f"--infra at the cluster running '{args.policy}'.")

    print(f"Fetching policy '{policy_name}' "
          f"(infra runs v{meta.get('version')}) ...", file=sys.stderr)
    policy_obj = xc.get_policy(namespace, policy_name)

    inputs = xc_api.normalize(args.tenant, namespace, infra, infra_obj, policy_obj)

    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(inputs, fh, indent=2)
        fh.write("\n")
    print(f"\nWrote {args.out}", file=sys.stderr)
    _summarize(inputs)

    if args.raw:
        for label, obj in (("infra", infra_obj), ("policy", policy_obj)):
            path = f"{args.out.rsplit('.', 1)[0]}_raw_{label}.json"
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(obj, fh, indent=2)
            print(f"Wrote {path}", file=sys.stderr)
    return 0


def _summarize(inputs: dict) -> None:
    out = sys.stderr
    xc = inputs["xc"]
    print("", file=out)
    print(f"  Tenant / namespace : {xc['tenant']} / {xc['namespace']}", file=out)
    print(f"  Infra              : {xc['infra']}  ({xc['infra_type']}, "
          f"{xc['deployment_mode']}, {xc['cluster_state']})", file=out)
    print(f"  Policy             : {xc['policy']}  deployed v"
          f"{xc['policy_version_deployed']}, latest v{xc['policy_version_latest']}",
          file=out)
    print(f"  Bot service        : {inputs['bot_service']['host']}:"
          f"{inputs['bot_service']['port']}", file=out)
    print(f"  Telemetry JS       : {inputs['js']['script_src']}", file=out)
    print(f"  Endpoints          : {len(inputs['endpoints'])}", file=out)
    for ep in inputs["endpoints"]:
        marks = ",".join(ep["methods"]) or "ANY"
        # GET_DOCUMENT is shown because it is what XC says, not because it is
        # the injection list -- 'build' asks for that separately.
        tag = "  <- XC GET_DOCUMENT" if ep.get("get_document") else ""
        desc = f" {ep['combine']} ".join(
            f"{m['op']} {m['value']}" + (" (nocase)" if m["nocase"] else "")
            + (" NOT" if m["negate"] else "") for m in ep["matches"])
        print(f"    - {ep['name'] or '(unnamed)'} [{marks}]: {desc}{tag}", file=out)
    for u in inputs.get("unsupported_endpoints", []):
        print(f"    ! {u['name']}: {u['reason']}", file=out)
    if inputs.get("mobile_endpoint_count"):
        print(f"  Mobile endpoints   : {inputs['mobile_endpoint_count']} "
              f"(skipped -- SDK, not JS)", file=out)
    print(f"  JS injection       : not in this file -- XC does not record which "
          f"pages\n                       need the <script>. 'build' asks.", file=out)
    print("", file=out)


# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------
def _match_vs(virtuals: list, vs: str, partition: str) -> dict | None:
    """The discovered virtual server the operator meant, or None.

    Bare names are not unique across partitions -- the whole point of the
    partition flag is that /prod/shop and /dev/shop are different applications
    -- so the requested partition decides between duplicates. A single
    unambiguous match anywhere wins even when the partitions disagree: that is
    the operator naming a real VS, and its own partition is then authoritative.
    """
    named = [v for v in virtuals if v["name"] == vs]
    if len(named) <= 1:
        return named[0] if named else None
    part = (partition or "Common").strip("/")
    hit = next((v for v in named if v.get("partition") == part), None)
    if not hit:
        where = ", ".join(sorted(v["fullPath"] or v["name"] for v in named))
        print(f"  ! {len(named)} virtual servers are named {vs} ({where}), none "
              f"in {part}. Building for {part} anyway -- name the VS as "
              f"/partition/{vs} to pick one.", file=sys.stderr)
    return hit


def _pool_selecting_irules(bip: BigIP | None, match: dict | None) -> list:
    """[(iRule name, [commands])] for iRules on the VS that pick a destination.

    Those override the generated policy at every iRule priority, so their
    presence is a reason not to use the policy at all. Only checkable with a
    BIG-IP to read; an offline build says so in the artifacts instead.
    """
    if not (bip and match and match.get("rules")):
        return []
    try:
        bodies = bip.irule_bodies(match["rules"])
    except Exception as e:
        print(f"  (could not read iRule bodies: {e})", file=sys.stderr)
        return []
    found = []
    for name in match["rules"]:
        cmds = irule_selects_pool(bodies.get(name, ""))
        if cmds:
            found.append((name, cmds))
            print(f"  ! iRule {name} selects a destination itself "
                  f"({', '.join(cmds)})", file=sys.stderr)
    return found


def _entrypoints(args, ask: Asker) -> list[str]:
    """Paths whose HTML response gets the telemetry <script>.

    Asked, not fetched. XC records which endpoints are protected; it does not
    record which pages carry the script that protects them -- those are the
    pages holding a form (or JS) that fires a protected endpoint, which is a
    property of the application's HTML. Nothing in the API describes it, so the
    honest options are "the operator knows" or "all of it".
    """
    given = []
    for p in (args.entrypoint or []):
        cleaned = xc_api.clean_path(p, anchor=True)
        if not cleaned:
            raise SystemExit(f"--entrypoint {p!r} is not a usable path.")
        given.append(cleaned)
    if given:
        return given

    if not ask.interactive:
        # Nobody to ask, so the fallback applies. build_plan warns about it;
        # explaining the choice to a log nobody is reading is just noise.
        return []
    print("\nJS injection scope\n"
          "  The telemetry <script> belongs on the pages carrying a form (or\n"
          "  JS) that fires a protected endpoint. XC does not record which\n"
          "  pages those are, so it cannot be fetched -- either you have\n"
          "  mapped them, or the script goes into every HTML response.",
          file=sys.stderr)
    if ask.choose("Have the entrypoint pages been mapped?",
                  ["all", "mapped"], "all",
                  ["No  -- inject across the whole application "
                   "(data group gets '/')",
                   "Yes -- type the entrypoint paths now"]) != "mapped":
        return []

    while True:
        raw = ask.text("Entrypoint paths, comma-separated "
                       "(e.g. /login,/account/transfer)")
        paths, bad = [], []
        for chunk in raw.split(","):
            if not chunk.strip():
                continue
            cleaned = xc_api.clean_path(chunk.strip(), anchor=True)
            (paths if cleaned else bad).append(cleaned or chunk.strip())
        if bad:
            print(f"  not usable as a path: {', '.join(bad)}", file=sys.stderr)
            continue
        if paths:
            return paths


def cmd_build(args) -> int:
    ask = Asker(not args.yes)

    try:
        with open(args.inputs, encoding="utf-8") as fh:
            inputs = json.load(fh)
    except FileNotFoundError:
        raise SystemExit(
            f"No inputs file at {args.inputs}. Run 'xcbot.py fetch' first.")
    problems = xc_api.check(inputs)
    if problems:
        raise SystemExit("Unusable inputs file:\n  - " + "\n  - ".join(problems))

    # Which VS? Ask the BIG-IP when we can, so the names are real ones.
    vs, default_pool = args.vs, args.default_pool
    bip = _bigip(args, ask) if args.bigip else None
    virtuals = []
    if bip:
        print(f"Reading virtual servers from {args.bigip} ...", file=sys.stderr)
        try:
            virtuals = bip.virtuals()
        except Exception as e:
            # Discovery is a convenience, not a dependency -- fall back to
            # asking rather than failing a build that needs no BIG-IP at all.
            print(f"  could not read virtual servers ({e})", file=sys.stderr)
            print("  continuing without discovery: no pick-list, no fallback "
                  "pool read off the VS, no collision or existing-iRule "
                  "warnings.", file=sys.stderr)
            if isinstance(e, HTTPError) and e.status == 401:
                print(f"  401 is the username or the password. --bigip-user is "
                      f"'{args.bigip_user}'; the password comes from BIGIP_PASS "
                      f"or the prompt.", file=sys.stderr)
            bip = None
        if bip and not virtuals:
            print("  (none found)", file=sys.stderr)
    if virtuals and not vs:
        labels = [f"{v['fullPath'] or v['name']}  ->  {v['destination']}  "
                  f"pool={v['pool'] or '(none)'}" for v in virtuals]
        vs = ask.choose("Which virtual server do you want to protect?",
                        [v["name"] for v in virtuals], vs, labels)

    vs = vs or ask.text("Which virtual server do you want to protect?")

    # A VS named as /prod/app carries its own partition: honour it rather than
    # making the operator repeat it in --partition, which is the commoner slip.
    if vs.startswith("/") and vs.count("/") >= 2:
        vs_part, vs = vs.strip("/").split("/", 1)
        if args.partition not in ("", "Common") and args.partition != vs_part:
            raise SystemExit(
                f"--partition {args.partition} conflicts with the virtual "
                f"server path /{vs_part}/{vs}. Drop one of the two.")
        args.partition = vs_part

    match = _match_vs(virtuals, vs, args.partition)
    if match:
        # Same reasoning: the pick-list spans partitions, so the VS the operator
        # chose is what decides which partition the objects are built in.
        if match.get("partition"):
            args.partition = match["partition"]
        if match["policies"] or match["rules"]:
            print(f"  note: {vs} already has policies="
                  f"{match['policies'] or '[]'} rules={match['rules'] or '[]'}",
                  file=sys.stderr)
        # Deliberately not prompted for. It only sets the rules' fallback-pool,
        # and leaving it empty makes the tmsh script read that off the VS when
        # it runs, which is both correct and free. --default-pool overrides.
        default_pool = default_pool or match["pool"]

    conflicts = _pool_selecting_irules(bip, match)
    entrypoints = _entrypoints(args, ask)

    try:
        plan = build_plan(inputs, vs=vs, default_pool=default_pool,
                          prefix=args.prefix, shape_header=args.shape_header,
                          partition=args.partition, inject_tag=args.inject_tag,
                          merge_op=args.merge_ops,
                          oneconnect_mask=args.oneconnect_mask,
                          entrypoints=entrypoints,
                          entrypoint_methods=args.entrypoint_methods,
                          pool_selecting_irules=conflicts)
    except ValueError as e:
        # Bad option values reach here; a traceback would bury the one line
        # that says which option to fix.
        raise SystemExit(str(e))

    if bip and not args.yes:
        _collision_check(bip, plan)

    want = {"ui": args.ui, "tmsh": args.tmsh, "as3": args.as3}
    if not any(want.values()):
        want = {k: True for k in want}

    os.makedirs(args.out_dir, exist_ok=True)
    written = []

    def write(name: str, text: str, mode: int = 0o644):
        path = os.path.join(args.out_dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text if text.endswith("\n") else text + "\n")
        os.chmod(path, mode)
        written.append(path)

    if want["ui"]:
        write(f"{vs}_botdefense_ui.md", render_ui(plan))
    if want["tmsh"]:
        write(f"{vs}_botdefense.sh", render_tmsh(plan), 0o755)
    if want["as3"]:
        write(f"{vs}_botdefense_as3.json", render_as3(plan))
    if want["ui"] or want["tmsh"]:
        write(f"{plan['irule']['name']}.tcl", plan["irule"]["text"])

    print("", file=sys.stderr)
    for w in plan["warnings"]:
        print(f"  ! {w}", file=sys.stderr)
    if plan["warnings"]:
        print("", file=sys.stderr)
    for path in written:
        print(f"Wrote {path}", file=sys.stderr)
    print(f"\nNothing has been sent to a BIG-IP. Review the files, then either "
          f"follow the UI steps, run the .sh on the box, or:\n"
          f"  python3 xcbot.py deploy --bigip HOST --tmsh "
          f"{os.path.join(args.out_dir, vs + '_botdefense.sh')}", file=sys.stderr)
    return 0


def _collision_check(bip: BigIP, plan: dict) -> None:
    """Say what the generated script will do with the names already taken.

    Not a gate. The script checks every object itself and either reuses it or
    stops without changing it, so a taken name is no longer a reason not to
    build. This asks the same question early, where a human is present and
    `--prefix` is still cheap to change.

    What is read is the provenance marker -- `description "xcbot:<hash>"`, or
    for `ltm rule` the same hash as a comment in the body, since that type has
    no description property. The marker sorts a taken name into one of three
    outcomes. What is deliberately *not* read is the object's content: that
    comparison lives in the artifact, in bash, and running a second copy of it
    here in Python is how the two would come to disagree about what "matches"
    means.

    Scoped to the target partition. The same name in another partition is
    expected -- that is how two applications get their own Bot Defense config --
    and reporting it would train the operator to ignore the report.
    """
    n = plan["names"]
    part = (plan["partition"] or "Common").strip("/")
    fps = fingerprints(plan)
    dg_names = {dg["name"] for dg in plan["datagroups"]}
    wanted = {
        "ltm/pool": [n["pool"]],
        "ltm/monitor/https": [n["monitor"]],
        "ltm/rule": [n["irule"]],
        "ltm/policy": [n["policy"]],
        "ltm/profile/html": [n["html_profile"]],
        "ltm/profile/one-connect": ([n["oneconnect"]]
                                    if plan["oneconnect"] else []),
        # The type, not the bare 'ltm/html-rule' collection: that one holds
        # pointers with no name of their own and would never match.
        "ltm/html-rule/tag-append-html": [n["html_rule"]],
        "ltm/data-group/internal": sorted(dg_names),
    }
    try:
        existing = bip.existing_objects(tuple(wanted))
    except Exception as e:
        print(f"  (could not check what is already on the box: {e})",
              file=sys.stderr)
        return

    mine, older, theirs = [], [], []
    for kind, names in wanted.items():
        for name in names:
            obj = (existing.get(kind) or {}).get(f"/{part}/{name}")
            if obj is None:
                continue
            if kind == "ltm/rule":
                m = re.search(r"# xcbot-fingerprint: ([0-9a-f]+)",
                              obj["body"] or "")
                live = m.group(1) if m else ""
            else:
                desc = obj["description"] or ""
                live = desc[6:] if desc.startswith("xcbot:") else ""
            label = f"{kind} /{part}/{name}"
            (mine if live and live == fps.get(name)
             else older if live else theirs).append(label)

    if not (mine or older or theirs):
        return
    out = ["", "  Some of these names are already taken on the BIG-IP. None of "
           "it blocks the build --",
           "  the generated script checks each object again on the box:"]
    for heading, group in (
            (["    Already this build's own -- will be reused:"], mine),
            (["    Made by an earlier build of this tool -- reused if the "
              "content still matches,",
              "    otherwise the script stops at that step and changes "
              "nothing:"], older),
            (["    Not created by this tool -- the script compares the content "
              "and either",
              "    reuses it, saying whose it is, or stops at that step:"],
             theirs)):
        if group:
            out += [""] + heading + [f"      - {c}" for c in group]
    if dg_names & {c.rsplit("/", 1)[-1] for c in mine + older + theirs}:
        out += ["", "    Data-group records are never rewritten by deploy, "
                "whatever the verdict above.",
                "    Reconcile them with: python3 xcbot.py sync --check"]
    out += ["", "  To build alongside what is there instead of onto it, pick a "
            "different --prefix.", ""]
    print("\n".join(out), file=sys.stderr)


# ---------------------------------------------------------------------------
# deploy
# ---------------------------------------------------------------------------
def cmd_deploy(args) -> int:
    ask = Asker(not args.yes)
    if not (args.tmsh_file or args.as3_file):
        raise SystemExit("Pass --tmsh FILE or --as3 FILE (the reviewed artifact).")
    bip = _bigip(args, ask, required=True)

    if args.tmsh_file:
        with open(args.tmsh_file, encoding="utf-8") as fh:
            script = fh.read()
        print(f"About to run {args.tmsh_file} on {args.bigip}.", file=sys.stderr)
        print("It creates objects and attaches them to the virtual server.",
              file=sys.stderr)
        if not args.yes and not ask.confirm("Proceed?", False):
            raise SystemExit("Aborted -- nothing was sent.")
        out, rc = bip.deploy_tmsh(script, os.path.basename(args.tmsh_file))
        print(out)
        if rc != 0:
            # The script stops itself when an object exists with different
            # content, and it says why on stderr, which is already in `out`.
            # Nothing to add here except the exit code, so that a caller in a
            # pipeline is not told a half-finished build succeeded.
            print(f"\n{args.tmsh_file} exited {rc} -- see the abort above. "
                  f"Nothing was attached to the virtual server unless the "
                  f"output says otherwise.", file=sys.stderr)
            return rc

    if args.as3_file:
        with open(args.as3_file, encoding="utf-8") as fh:
            decl = json.load(fh)
        decl.pop("_notes", None)          # our own annotation, not AS3 schema
        version = bip.as3_version()
        if not version:
            raise SystemExit(
                "AS3 is not installed on this BIG-IP. Install the f5-appsvcs "
                "RPM, or deploy the tmsh artifact instead.")
        print(f"AS3 {version} detected on {args.bigip}.", file=sys.stderr)
        if not args.yes and not ask.confirm(
                f"POST {args.as3_file} to /mgmt/shared/appsvcs/declare?", False):
            raise SystemExit("Aborted -- nothing was sent.")
        print(bip.deploy_as3(decl))
    return 0


# ---------------------------------------------------------------------------
# sync
# ---------------------------------------------------------------------------
def _notify(args, line: str, report: str) -> None:
    """One syslog line, and the full diff appended to the report file.

    logger, not a socket: it puts the line in /var/log/ltm beside what the
    generated iRule already logs, so an existing forwarder picks it up with no
    new configuration. Failure to log is never allowed to fail the run -- the
    diff has already been printed to stdout by the time this is called.
    """
    try:
        subprocess.run(["/bin/logger", "-p", "local0.notice", "-t", "xcbot",
                        line], check=False)
    except OSError:
        pass                                # not a BIG-IP, or no logger

    path = args.log_file
    if not path:
        return
    try:
        # Truncate rather than rotate: nothing on the box rotates a file we
        # invent, and an unbounded log on /var is worse than a lost history.
        if os.path.exists(path) and os.path.getsize(path) > 1_000_000:
            with open(path, encoding="utf-8", errors="replace") as fh:
                keep = fh.read()[-200_000:]
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(f"[truncated at 1MB]\n{keep}")
        stamp = datetime.datetime.now().isoformat(timespec="seconds")
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(f"\n===== {stamp}  {line}\n{report}\n")
    except OSError as e:
        print(f"  (could not write {path}: {e})", file=sys.stderr)


def _sync_transport(args, ask: Asker, partition: str):
    """REST when --bigip was given, local tmsh otherwise."""
    if args.bigip:
        return sync.RestTransport(_bigip(args, ask, required=True), partition)
    if not os.path.exists("/usr/bin/tmsh") and not os.path.exists("/bin/tmsh"):
        raise SystemExit(
            "No --bigip given, so this expects to be running ON a BIG-IP, but "
            "there is no tmsh here. Pass --bigip HOST to work over iControl "
            "REST instead.")
    return sync.LocalTransport(partition)


def cmd_sync(args) -> int:
    if bool(args.check) == bool(args.apply_file):
        raise SystemExit("Pass exactly one of --check or --apply FILE.")
    return _sync_apply(args) if args.apply_file else _sync_check(args)


def _sync_check(args) -> int:
    ask = Asker(not args.yes)
    partition = (args.partition or "Common").strip("/")

    if not os.path.exists(args.inputs):
        raise SystemExit(
            f"No {args.inputs}. sync compares XC against the box, and it takes "
            f"the tenant, namespace and infra to ask about from the inputs file "
            f"that 'fetch' wrote. Run fetch first, or pass --inputs PATH.")
    with open(args.inputs, encoding="utf-8") as fh:
        old_inputs = json.load(fh)
    old_xc = old_inputs.get("xc") or {}
    tenant = args.tenant or old_xc.get("tenant", "")
    namespace = args.namespace or old_xc.get("namespace", "")
    infra = args.infra or old_xc.get("infra", "")
    if not (tenant and namespace and infra):
        raise SystemExit(
            f"{args.inputs} does not name a tenant, namespace and infra, and "
            f"they were not passed. Re-run fetch, or pass --tenant/--namespace/"
            f"--infra.")

    # --- what XC says now
    print(f"Checking XC '{infra}' in {tenant}/{namespace} ...", file=sys.stderr)
    xc = xc_api.XC(tenant, _token(args), verify_tls=not args.no_verify_tls)
    infra_obj = xc.get_infra(namespace, infra)
    meta = ((infra_obj.get("spec") or {}).get("bot_endpoint_policy_metadata")) or {}
    policy_name = meta.get("name") or ""
    if not policy_name:
        raise SystemExit(f"Infra '{infra}' references no Bot Endpoint Policy.")
    policy_obj = xc.get_policy(namespace, policy_name)
    new_inputs = xc_api.normalize(tenant, namespace, infra, infra_obj, policy_obj)

    want, dmeta = sync.desired_state(new_inputs, args.prefix, args.merge_ops,
                                     partition)
    if not want:
        raise SystemExit(
            "The XC policy yields no data groups at all -- no protected "
            "endpoints and no egress addresses. Nothing to compare.")

    # --- what the box says now
    transport = _sync_transport(args, ask, partition)
    print(f"Reading data groups via {transport.label} ...", file=sys.stderr)
    ep_prefix = dmeta["ep_prefix"]
    # Read the union of what XC wants and what is actually there under our
    # endpoint prefix. Looking up only the expected names would make a bucket
    # the policy has dropped invisible -- nothing expects it, which is exactly
    # the thing worth reporting.
    on_box = transport.list_data_groups(ep_prefix)
    live = transport.read_data_groups(sorted(set(want) | set(on_box)))

    # A prefix that matches nothing is the difference between "XC added
    # everything" and "you named the wrong object set". Refuse rather than
    # report a diff that is really a typo.
    if not any(live.get(k) is not None for k in want
               if k.startswith(ep_prefix)):
        raise SystemExit(
            f"No data group under '{ep_prefix}-*' exists on the box, so there "
            f"is nothing this could be a diff against. Either the config was "
            f"never deployed, or --prefix is wrong (it is '{args.prefix}'; the "
            f"names it looked for are: "
            f"{', '.join(sorted(k for k in want if k.startswith(ep_prefix)))}).")

    delta = sync.diff(want, live, dmeta, old_inputs, new_inputs)

    # --- report
    staged = review = ""
    if delta.has_records:
        staged = os.path.join(args.stage_dir,
                              f"xcbot-sync-{_stamp()}.sh")
    if delta.has_review:
        review = os.path.join(args.stage_dir,
                              f"xcbot-sync-{_stamp()}-review.sh")
    report = sync.format_delta(delta, args.prefix, partition, staged, review)
    print(report)

    if staged:
        _write(staged, sync.render_sync_script(
            delta, args.prefix, partition,
            sync.format_delta(delta, args.prefix, partition)), 0o750)
        _write(staged[:-3] + ".json",
               sync.sidecar(delta, args.prefix, partition, want, live), 0o640)
    if review:
        _write(review, sync.render_review_script(delta, args.prefix, partition),
               0o640)

    _notify(args, sync.summary_line(delta), report)
    return delta.exit_code()


def _sync_apply(args) -> int:
    ask = Asker(not args.yes)
    path = args.apply_file
    side_path = path[:-3] + ".json" if path.endswith(".sh") else path + ".json"
    if not os.path.exists(side_path):
        raise SystemExit(
            f"No {side_path} beside {path}. --apply only runs a script that "
            f"'sync --check' staged, because the sidecar is what records the "
            f"box state the diff was computed against.")
    with open(side_path, encoding="utf-8") as fh:
        side = json.load(fh)
    with open(path, encoding="utf-8") as fh:
        script = fh.read()

    partition = side.get("partition") or "Common"
    transport = _sync_transport(args, ask, partition)
    live = transport.read_data_groups(side.get("checked") or [])
    now = sync.fingerprint(live, side.get("checked") or [])
    if now != side.get("fingerprint"):
        raise SystemExit(
            f"The box changed since this was staged (fingerprint "
            f"{side.get('fingerprint')} -> {now}), so the diff you would be "
            f"approving is not the diff that would be applied.\n"
            f"Re-run 'sync --check' and review the new one.")

    # The diff comes out of the artifact itself, not from recomputing it: what
    # is being approved is what this file will do.
    print(f"--- {path}", file=sys.stderr)
    for line in script.splitlines():
        if not line.startswith("#"):
            break                            # header over, commands start here
        if line.startswith("#!") or line.startswith("# state-fingerprint"):
            continue
        print(line[2:] if line.startswith("# ") else line[1:])
    print()
    print("The commands it will run:", file=sys.stderr)
    for line in script.splitlines():
        if line.startswith("tmsh"):
            print(f"  {line}")
    print()
    if not args.yes and not ask.confirm(
            f"Apply these record changes via {transport.label}?", False):
        raise SystemExit("Aborted -- nothing was written.")

    out = transport.run_script(script, os.path.basename(path))
    print(out)
    _notify(args, f"applied {os.path.basename(path)}: "
                  f"{len(side.get('records') or {})} data group(s)", out)
    return 0


def _stamp() -> str:
    return datetime.datetime.now().strftime("%Y%m%d-%H%M%S")


def _write(path: str, text: str, mode: int) -> None:
    d = os.path.dirname(path)
    if d and not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    try:
        os.chmod(path, mode)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args(argv: list[str]):
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)

    def bigip_opts(p, required=False):
        p.add_argument("--bigip", default="",
                       help="BIG-IP management address"
                            + ("" if required else " (optional: enables VS "
                                                   "discovery and collision checks)"))
        p.add_argument("--bigip-user", default="admin")
        p.add_argument("--verify-bigip-tls", action="store_true",
                       help="Verify the BIG-IP certificate (off by default -- "
                            "the device certificate is self-signed)")

    f = sub.add_parser("fetch", help="fetch XC data into a local inputs file")
    f.add_argument("--tenant", required=True, help="XC tenant, e.g. acme")
    f.add_argument("--namespace", default="", help="prompted for if omitted")
    f.add_argument("--infra", default="",
                   help="Bot Infrastructure; decides the policy and the service "
                        "host. Prompted for if omitted")
    f.add_argument("--policy", default="",
                   help="optional cross-check: fail if the infra runs a "
                        "different Bot Endpoint Policy")
    f.add_argument("--out", default=DEFAULT_INPUTS)
    f.add_argument("--raw", action="store_true",
                   help="also save the unmodified XC responses")
    f.add_argument("--token-file", default="", metavar="PATH",
                   help=f"read the API token from PATH instead of "
                        f"./{DEFAULT_TOKEN_FILE}")
    f.add_argument("--no-verify-tls", action="store_true",
                   help="skip TLS verification against XC (lab only)")
    f.add_argument("--yes", "-y", action="store_true",
                   help="never prompt; every answer must come from an option")
    f.set_defaults(func=cmd_fetch)

    b = sub.add_parser("build", help="render the configuration artifacts")
    b.add_argument("--inputs", default=DEFAULT_INPUTS)
    b.add_argument("--vs", default="",
                   help="virtual server to protect. /partition/name sets "
                        "--partition too")
    b.add_argument("--default-pool", default="",
                   help="override the rules' fallback-pool. Rarely needed: left "
                        "unset, the tmsh script reads the pool off the virtual "
                        "server when it runs")
    b.add_argument("--prefix", default="bot-defense",
                   help="prefix for every object name created (default: "
                        "bot-defense)")
    b.add_argument("--shape-header", default="shape-header",
                   help="header Bot Defense sets on traffic it hands back; the "
                        "loop guard matches on its absence")
    b.add_argument("--inject-tag", default="head", choices=["head", "body"],
                   help="tag the telemetry <script> is appended to")
    b.add_argument("--entrypoint", action="append", metavar="PATH",
                   help="page whose HTML response gets the telemetry <script>; "
                        "repeat once per page. XC does not record these, so "
                        "they are asked for. Omit and the data group gets '/', "
                        "which injects into every HTML response")
    b.add_argument("--entrypoint-methods", default="GET", metavar="VERBS",
                   help="methods recorded against each entrypoint (default "
                        "GET: injection happens on the document request)")
    b.add_argument("--oneconnect-mask", default="255.255.255.255",
                   metavar="MASK",
                   help="source mask for the OneConnect profile (default "
                        "255.255.255.255: confine serverside connection reuse "
                        "to one client address). Empty string skips the "
                        "profile entirely")
    b.add_argument("--merge-ops", default="", metavar="OP",
                   choices=["", "contains", "starts-with", "ends-with", "equals"],
                   help="collapse to one data group and one rule per HTTP "
                        "method by rewriting every path matcher to OP. Fewer "
                        "objects, but no longer what XC specified -- 'contains' "
                        "is the only OP that cannot miss a protected endpoint")
    b.add_argument("--partition", default="Common", metavar="NAME",
                   help="BIG-IP partition to build in (default: Common). A "
                        "full set of objects is created inside it rather than "
                        "shared out of /Common, so partitions serving "
                        "different XC namespaces can point at different Bot "
                        "Defense policies and infrastructure. Implied by a "
                        "virtual server named as /partition/name")
    b.add_argument("--out-dir", default="out")
    b.add_argument("--ui", action="store_true", help="write the GUI walkthrough")
    b.add_argument("--tmsh", action="store_true", help="write the tmsh script")
    b.add_argument("--as3", action="store_true", help="write the AS3 declaration")
    bigip_opts(b)
    b.add_argument("--yes", "-y", action="store_true",
                   help="never prompt; every answer must come from an option")
    b.set_defaults(func=cmd_build)

    d = sub.add_parser("deploy", help="push an already-generated artifact")
    d.add_argument("--tmsh", dest="tmsh_file", default="",
                   help="the generated .sh to upload and run")
    d.add_argument("--as3", dest="as3_file", default="",
                   help="the generated AS3 .json to POST")
    bigip_opts(d, required=True)
    d.add_argument("--yes", "-y", action="store_true",
                   help="skip the confirmation prompt")
    d.set_defaults(func=cmd_deploy)

    s = sub.add_parser(
        "sync", help="check whether the XC policy has moved, and apply the "
                     "record-level part of the difference")
    s.add_argument("--check", action="store_true",
                   help="compare XC against the box; print the diff, log it, "
                        "and stage an apply script. Writes no BIG-IP config")
    s.add_argument("--apply", dest="apply_file", default="", metavar="PATH",
                   help="apply a script that --check staged, after showing the "
                        "diff and asking")
    s.add_argument("--inputs", default=DEFAULT_INPUTS,
                   help="the fetched file; supplies the tenant, namespace and "
                        "infra to re-check, and the previous values that "
                        "non-endpoint drift is compared against")
    s.add_argument("--prefix", default="bot-defense",
                   help="the prefix the deployed objects were built with. Must "
                        "match, or there is nothing to diff against")
    s.add_argument("--partition", default="Common", metavar="NAME")
    s.add_argument("--merge-ops", default="", metavar="OP",
                   choices=["", "contains", "starts-with", "ends-with", "equals"],
                   help="the --merge-ops the objects were built with, if any. "
                        "Wrong value here means wrong data-group names")
    s.add_argument("--stage-dir", default="/var/tmp", metavar="DIR",
                   help="where the staged script and its sidecar go "
                        "(default /var/tmp)")
    s.add_argument("--log-file", default="/var/log/xcbot-sync.log", metavar="PATH",
                   help="full diff is appended here; a one-line summary always "
                        "goes to syslog via logger. Empty string disables the file")
    s.add_argument("--tenant", default="", help="override the inputs file")
    s.add_argument("--namespace", default="", help="override the inputs file")
    s.add_argument("--infra", default="", help="override the inputs file")
    s.add_argument("--token-file", default="", metavar="PATH",
                   help=f"read the API token from PATH instead of "
                        f"./{DEFAULT_TOKEN_FILE}")
    s.add_argument("--no-verify-tls", action="store_true",
                   help="skip TLS verification against XC (lab only)")
    bigip_opts(s)
    s.add_argument("--yes", "-y", action="store_true",
                   help="with --apply, skip the confirmation. With --check it "
                        "only suppresses prompting; --check never writes config")
    s.set_defaults(func=cmd_sync)

    return ap.parse_args(argv)


if __name__ == "__main__":
    args = parse_args(sys.argv[1:])
    try:
        raise SystemExit(args.func(args))
    except HTTPError as e:                # must precede RuntimeError -- subclass
        sys.exit(str(e))
    except urllib.error.URLError as e:
        sys.exit(f"Network error: {e.reason}")
    except RuntimeError as e:
        sys.exit(str(e))
