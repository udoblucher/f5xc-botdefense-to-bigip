#!/usr/bin/env python3
"""bigip_api.py -- BIG-IP iControl REST: read for discovery, write for deploy.

Reading is what the normal path uses -- it turns "which VS do you want?" into a
pick-list with each VS's current default pool, profiles and policies already
filled in, so the operator does not have to type names that must match exactly.

Writing is opt-in (`xcbot deploy`) and reuses the exact artifact that was
reviewed: the tmsh script is uploaded and piped through tmsh, the AS3
declaration is POSTed as-is. Nothing is regenerated at deploy time.
"""

from __future__ import annotations

import json
import posixpath

from rest import HTTPError, request, request_json


class BigIP:
    def __init__(self, host: str, user: str, password: str,
                 verify_tls: bool = False):
        self.host = host
        self.auth = (user, password)
        self.verify = verify_tls

    @property
    def _base(self) -> str:
        return f"https://{self.host}/mgmt"

    def _get(self, path: str):
        return request_json("GET", self._base + path, auth=self.auth,
                            verify=self.verify, timeout=30)

    # -- discovery -----------------------------------------------------------
    def virtuals(self) -> list[dict]:
        """Every virtual server with the fields the build actually needs."""
        data = self._get("/tm/ltm/virtual?expandSubcollections=true")
        out = []
        for v in (data.get("items") or []):
            out.append({
                "name": v.get("name", ""),
                "fullPath": v.get("fullPath", ""),
                "destination": (v.get("destination") or "").split("/")[-1],
                "pool": posixpath.basename(v.get("pool", "")) if v.get("pool") else "",
                "profiles": sorted(p.get("name", "") for p in
                                   ((v.get("profilesReference") or {}).get("items") or [])),
                "policies": sorted(p.get("name", "") for p in
                                   ((v.get("policiesReference") or {}).get("items") or [])
                                   if isinstance(p, dict)),
                "rules": [posixpath.basename(r) for r in (v.get("rules") or [])],
            })
        return sorted(out, key=lambda x: x["name"])

    def irule_bodies(self, names) -> dict[str, str]:
        """Body text of the named iRules, keyed by name.

        Used to spot an existing iRule that selects a pool, which would
        override the generated policy. One list call rather than a GET per
        name: iRule names can be partition-qualified on the virtual server and
        the whole list is small.
        """
        wanted = {posixpath.basename(nm) for nm in (names or []) if nm}
        if not wanted:
            return {}
        try:
            data = self._get("/tm/ltm/rule")
        except Exception:
            return {}
        return {i["name"]: i.get("apiAnonymous") or ""
                for i in (data.get("items") or [])
                if isinstance(i, dict) and i.get("name") in wanted}

    def as3_version(self) -> str | None:
        """AS3 version string, or None when the extension is not installed."""
        try:
            info = self._get("/shared/appsvcs/info")
        except HTTPError:
            return None
        except Exception:
            return None
        return info.get("version") if isinstance(info, dict) else None

    def existing_names(self, kinds: tuple[str, ...] = (
            "ltm/pool", "ltm/monitor/https", "ltm/data-group/internal",
            "ltm/rule", "ltm/policy", "ltm/profile/html", "ltm/html-rule")
            ) -> dict[str, list[str]]:
        """Current object names per kind -- used to warn about collisions."""
        found = {}
        for kind in kinds:
            try:
                data = self._get(f"/tm/{kind}")
            except Exception:
                continue
            found[kind] = sorted(i.get("name", "")
                                 for i in (data.get("items") or []))
        return found

    # -- deploy --------------------------------------------------------------
    def _upload(self, text: str, remote_name: str) -> str:
        """Push a file into /var/config/rest/downloads/ and return its path."""
        data = text.encode()
        request("POST", f"{self._base}/shared/file-transfer/uploads/{remote_name}",
                headers={"Content-Type": "application/octet-stream",
                         "Content-Range": f"0-{len(data) - 1}/{len(data)}"},
                data=data, auth=self.auth, verify=self.verify, timeout=120)
        return f"/var/config/rest/downloads/{remote_name}"

    def _bash(self, cmd: str) -> str:
        out = request_json("POST", f"{self._base}/tm/util/bash", auth=self.auth,
                           obj={"command": "run", "utilCmdArgs": f"-c '{cmd}'"},
                           verify=self.verify, timeout=300)
        return (out or {}).get("commandResult", "") if isinstance(out, dict) else ""

    def deploy_tmsh(self, script_text: str, remote_name: str) -> str:
        """Upload the generated bash/tmsh script and run it on the box.

        Uploaded rather than inlined: _bash single-quotes the command it runs,
        and the script is full of single quotes of its own.
        """
        path = self._upload(script_text, remote_name)
        return self._bash(f"bash {path} 2>&1")

    def deploy_as3(self, declaration: dict) -> str:
        """POST the AS3 declaration to the appsvcs endpoint."""
        if not self.as3_version():
            raise RuntimeError(
                "AS3 is not installed on this BIG-IP (no /mgmt/shared/appsvcs). "
                "Install the f5-appsvcs RPM, or deploy the tmsh artifact instead.")
        res = request_json("POST", f"{self._base}/shared/appsvcs/declare",
                           auth=self.auth, obj=declaration,
                           verify=self.verify, timeout=600)
        return json.dumps(res, indent=2)
