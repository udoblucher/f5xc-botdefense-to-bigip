#!/usr/bin/env python3
"""xc_api.py -- fetch from the F5 Distributed Cloud (XC) API and normalize.

Two responsibilities, nothing else:

  XC          thin API client (list namespaces / infras, get infra, get policy)
  normalize() turn the two raw XC objects into the flat inputs file that the
              renderers consume

Everything downstream reads the normalized file, never the raw XC JSON, so the
XC response shape is understood in exactly one place: this module.

API notes
---------
Bot Defense lives under /api/shape/bot/, NOT the /api/config/ group used by most
XC objects -- /api/config/ answers 404 "API Group could not be determined". The
collection is spelled `bot_endpoint_policys` (sic).

  Base URL   https://<tenant>.console.ves.volterra.io
  Auth       Authorization: APIToken <token>
  Infra      GET /api/shape/bot/namespaces/<ns>/bot_infrastructures[/<name>]
  Policy     GET /api/shape/bot/namespaces/<ns>/bot_endpoint_policys/<name>

The Bot Infrastructure is the entry point, not the policy: it names the policy
version that cluster is actually running AND advertises the host name the
BIG-IP has to send traffic to. Asking for a policy without an infra would give
you endpoints with nowhere to send them.
"""

from __future__ import annotations

import datetime
import re
import urllib.parse

from rest import request_json

SCHEMA = "xcbot/1"

# XC BP_METHOD_* -> (HTTP verb, is a JS-injection entrypoint).
# GET_DOCUMENT is XC's marker for "a browser asking for an HTML document",
# which is exactly where the telemetry <script> has to be injected.
_METHODS = {
    "BP_METHOD_GET":          ("GET", False),
    "BP_METHOD_GET_DOCUMENT": ("GET", True),
    "BP_METHOD_POST":         ("POST", False),
    "BP_METHOD_PUT":          ("PUT", False),
    "BP_METHOD_PATCH":        ("PATCH", False),
    "BP_METHOD_DELETE":       ("DELETE", False),
    "BP_METHOD_HEAD":         ("HEAD", False),
    "BP_METHOD_OPTIONS":      ("OPTIONS", False),
    "BP_METHOD_TRACE":        ("TRACE", False),
}

# XC path matcher -> the operator name used by both tmsh and AS3.
_OPS = {
    "exact_value":      "equals",
    "start_with_value": "starts-with",
    "end_with_value":   "ends-with",
    "contain_value":    "contains",
}

# How the matchers inside one endpoint combine.
_COMBINE = {"all_path": "all", "path_or": "or",
            "path_and": "and", "path_none": "none"}

# Health check for the F5-hosted Bot Defense service.
HEALTH_PATH = "/sedcloudapi/health"


# ---------------------------------------------------------------------------
# Value hygiene. These strings end up inside tmsh values, TCL, a shell script
# and an HTML attribute, so anything that could break out of one of those is
# rejected outright rather than escaped four different ways.
# ---------------------------------------------------------------------------
_PATH_OK = re.compile(r"^[A-Za-z0-9\-._~/%:@!&()*+,;=]+$")
_SRC_OK = re.compile(r"^/[A-Za-z0-9\-._~/%:@!&()*+,;=?]*$")
_HOST_OK = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9\-._]{0,251}[A-Za-z0-9])?$")
_MAXLEN = 512


def clean_path(value: str, anchor: bool = False) -> str | None:
    """A path or path fragment safe for every output format, else None.

    anchor=True forces a leading '/' (right for equals / starts-with, wrong for
    ends-with / contains where the fragment is deliberately unanchored).
    """
    if not isinstance(value, str):
        return None
    v = value.strip()
    if not v or len(v) > _MAXLEN or not _PATH_OK.match(v):
        return None
    if anchor and not v.startswith("/"):
        v = "/" + v
    return re.sub(r"/{2,}", "/", v)


def clean_script_src(value: str) -> str | None:
    """The js_download_path as it goes into <script src="...">.

    Same rules as clean_path plus '?', because the download path legitimately
    carries a query string (XC's default is /common.js?single). Rejects the
    quote and angle-bracket characters that would break out of the tag.
    """
    if not isinstance(value, str):
        return None
    v = value.strip()
    if not v:
        return None
    if not v.startswith("/"):
        v = "/" + v
    return v if len(v) <= _MAXLEN and _SRC_OK.match(v) else None


def clean_host(value: str) -> str | None:
    """A DNS host name, else None. IPv6 literals are rejected, not half-kept."""
    if not isinstance(value, str):
        return None
    v = value.strip()
    return v if v and len(v) <= 253 and _HOST_OK.match(v) else None


def _dig(obj, *keys):
    for k in keys:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(k)
    return obj


# ---------------------------------------------------------------------------
# API client
# ---------------------------------------------------------------------------
class XC:
    def __init__(self, tenant: str, token: str, verify_tls: bool = True):
        if not token:
            raise RuntimeError(
                "No XC API token. Set F5XC_API_TOKEN, or pass --token-file.")
        self.tenant = tenant
        self.token = token
        self.verify_tls = verify_tls

    @property
    def base_url(self) -> str:
        return f"https://{self.tenant}.console.ves.volterra.io"

    def _get(self, path: str):
        return request_json("GET", self.base_url + path,
                            headers={"Authorization": f"APIToken {self.token}"},
                            verify=self.verify_tls, timeout=30)

    @staticmethod
    def _q(s: str) -> str:
        return urllib.parse.quote(s, safe="")

    def list_namespaces(self) -> list[str]:
        data = self._get("/api/web/namespaces")
        return sorted(i.get("name", "") for i in (data.get("items") or [])
                      if isinstance(i, dict) and i.get("name"))

    def list_infras(self, ns: str) -> list[str]:
        data = self._get(f"/api/shape/bot/namespaces/{self._q(ns)}"
                         f"/bot_infrastructures")
        return sorted(i.get("name", "") for i in (data.get("items") or [])
                      if isinstance(i, dict) and i.get("name"))

    def get_infra(self, ns: str, name: str) -> dict:
        return self._get(f"/api/shape/bot/namespaces/{self._q(ns)}"
                         f"/bot_infrastructures/{self._q(name)}")

    def get_policy(self, ns: str, name: str) -> dict:
        return self._get(f"/api/shape/bot/namespaces/{self._q(ns)}"
                         f"/bot_endpoint_policys/{self._q(name)}")


# ---------------------------------------------------------------------------
# Normalization -- raw XC objects in, inputs file out
# ---------------------------------------------------------------------------
def _service_host(infra: dict) -> tuple[str | None, list[str], list[str]]:
    """(primary host, regional hosts, egress IPs) for the Bot Defense service.

    Preference order matters. `cloud_hosted.infra_host_name` is the global,
    geo-routed name for an F5-hosted cluster -- the one a BIG-IP pool should
    point at. Regional ingress names are returned separately as alternates.

    Deliberately NOT used as pool members: `egress[]` (addresses Shape sends
    *from*, i.e. what you allowlist at the origin) and `host_names[]` /
    `ip_addresses[]` (the *protected app's* own domains -- pooling those would
    aim the BIG-IP back at itself).
    """
    spec = infra.get("spec") or {}
    ch = spec.get("cloud_hosted") if isinstance(spec.get("cloud_hosted"), dict) else {}

    primary = clean_host(ch.get("infra_host_name") or spec.get("infra_host_name") or "")
    regional, egress = [], []
    for src in (ch, spec):
        for ing in (src.get("ingress") or []):
            h = clean_host((ing or {}).get("host_name", ""))
            if h and h != primary and h not in regional:
                regional.append(h)
        for eg in (src.get("egress") or []):
            ip = (eg or {}).get("ip_address", "")
            if isinstance(ip, str) and ip and ip not in egress:
                egress.append(ip)
    if not primary and regional:            # fall back to a regional ingress
        primary, regional = regional[0], regional[1:]
    return primary, regional, egress


def _matches(path_op: dict) -> tuple[str, list[dict]]:
    """A bot_defensePathOperator -> (combine, [{op, value, nocase, negate}])."""
    if not isinstance(path_op, dict):
        return "all", [{"op": "starts-with", "value": "/",
                        "nocase": False, "negate": False}]
    for xc_key, combine in _COMBINE.items():
        if xc_key not in path_op:
            continue
        if combine == "all":
            return "all", [{"op": "starts-with", "value": "/",
                            "nocase": False, "negate": False}]
        arr = (path_op[xc_key] or {}).get("path_match") or []
        out = []
        for m in arr:
            if not isinstance(m, dict):
                continue
            for xk, op in _OPS.items():
                leaf = m.get(xk)
                if not isinstance(leaf, dict):
                    continue
                val = clean_path(leaf.get("value", ""),
                                 anchor=op in ("equals", "starts-with"))
                if val:
                    out.append({"op": op, "value": val,
                                "nocase": bool(leaf.get("case_insensitive")),
                                "negate": bool(leaf.get("not"))})
                break
        return combine, out
    return "all", [{"op": "starts-with", "value": "/",
                    "nocase": False, "negate": False}]


def normalize(tenant: str, ns: str, infra_name: str,
              infra: dict, policy: dict) -> dict:
    """The single place that turns XC's schema into our own."""
    spec = infra.get("spec") or {}
    pspec = policy.get("spec") or {}
    content = pspec.get("endpoint_policy_content") or {}

    meta = spec.get("bot_endpoint_policy_metadata") or {}
    policy_name = meta.get("name") or ""

    host, regional, egress = _service_host(infra)

    script_src = clean_script_src(content.get("js_download_path") or "")
    # The LTM policy matches on path only, so the data-group record is the
    # path with any query string stripped; the <script src> keeps the query.
    js_match = clean_path(script_src.split("?", 1)[0], anchor=True) if script_src else None

    endpoints, unsupported = [], []
    raw = ((content.get("protected_web_endpoints") or {})
           .get("protected_web_endpoints") or [])
    for ep in raw:
        if not isinstance(ep, dict):
            continue
        name = _dig(ep, "metadata", "name") or ""
        if _dig(ep, "metadata", "disable"):
            unsupported.append({"name": name, "reason": "disabled in XC"})
            continue
        combine, matches = _matches(ep.get("path"))
        if combine in ("and", "none"):
            unsupported.append({
                "name": name,
                "reason": f"path_{combine} combiner has no single-rule LTM "
                          f"policy equivalent -- configure this endpoint by hand"})
            continue
        if not matches:
            unsupported.append({"name": name,
                                "reason": "no usable path matcher after validation"})
            continue
        methods, entrypoint = [], False
        for m in (ep.get("http_methods") or []):
            verb, is_doc = _METHODS.get(m, (None, False))
            if verb:
                entrypoint = entrypoint or is_doc
                if verb not in methods:
                    methods.append(verb)
        endpoints.append({"name": name, "methods": methods,
                          "entrypoint": entrypoint, "combine": combine,
                          "matches": matches})

    mobile = len(((content.get("protected_mobile_endpoints") or {})
                  .get("protected_mobile_endpoints") or []))

    hc_host = ".".join(host.split(".")[-2:]) if host else ""

    return {
        "schema": SCHEMA,
        "fetched_at": datetime.datetime.now(datetime.timezone.utc)
                              .strftime("%Y-%m-%dT%H:%M:%SZ"),
        "xc": {
            "tenant": tenant,
            "console_url": f"https://{tenant}.console.ves.volterra.io",
            "namespace": ns,
            "infra": infra_name,
            "infra_type": spec.get("infra_type", ""),
            "traffic_type": spec.get("traffic_type", ""),
            "deployment_mode": spec.get("deployment_mode", ""),
            "cluster_state": spec.get("cluster_state", ""),
            "policy": policy_name,
            "policy_version_deployed": str(meta.get("version") or ""),
            "policy_version_latest": str(pspec.get("latest_version") or ""),
        },
        "bot_service": {
            "host": host or "",
            "port": 443,
            "regional_hosts": regional,
            "egress_ips": egress,
            "health_check": {"path": HEALTH_PATH, "host": hc_host},
        },
        "js": {"script_src": script_src or "", "match_path": js_match or ""},
        "endpoints": endpoints,
        "unsupported_endpoints": unsupported,
        "mobile_endpoint_count": mobile,
        "cookies": [c.get("name", "") for c in (pspec.get("cookies") or [])
                    if isinstance(c, dict) and c.get("name")],
    }


def check(inputs: dict) -> list[str]:
    """Fatal problems with an inputs file, as human-readable strings."""
    bad = []
    if inputs.get("schema") != SCHEMA:
        bad.append(f"inputs file schema is {inputs.get('schema')!r}, "
                   f"expected {SCHEMA!r} -- re-run 'fetch'")
    if not (inputs.get("bot_service") or {}).get("host"):
        bad.append("no Bot Defense service host in the infra object -- the "
                   "pool would have no member")
    if not (inputs.get("js") or {}).get("match_path"):
        bad.append("no js_download_path in the policy -- there is no telemetry "
                   "script to inject or route")
    if not inputs.get("endpoints"):
        bad.append("no usable protected web endpoints in the policy")
    return bad
