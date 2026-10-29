#!/usr/bin/env python3
"""Detection-only inventory triage for CVE-2026-111497 (Node2Shell).

CVE-2026-111497 is an out-of-bounds write in Google's Brotli decoder
(c/dec/decode.c), in Brotli 1.0.3 through 1.2.0. Node.js bundles that
decoder, so a Node.js process that decompresses attacker-controlled Brotli
data (a request body through Express 5 / body-parser 2.x, or a fetched
response through fetch() / node:zlib) can crash, leak process memory, or
run attacker code. CISA added the CVE to its Known Exploited
Vulnerabilities catalog on 2026-10-27.

This tool never touches the network and never sends a Brotli payload,
crafted or otherwise. It inventories the copies of the vulnerable code
that already live on a machine or in a project tree:

  * node and bun binaries (PATH, plus any --scan-dir tree)
  * Python brotli / brotlicffi packages in the current environment
  * .nvmrc pins, package.json engines and body-parsing dependencies,
    and Dockerfile node: base-image tags in a project tree

That is deliberately the half a network scanner cannot see. Assetnote's
free node2shell-scanner (released 2026-10-25) probes HTTP endpoints from
the network, route by route; it says itself it does not find fetchers or
Python clients, and one clean route does not clear the others. This tool
finds the runtimes and libraries sitting on disk instead. Use both.

Usage:
    python3 node2shell_inventory_scanner.py
    python3 node2shell_inventory_scanner.py --scan-dir /srv/myapp --json
    python3 node2shell_inventory_scanner.py --scan-dir ~/projects/api --no-path

Exit codes: 2 = a vulnerable or end-of-life runtime/library was found,
0 = nothing vulnerable found (UNKNOWN findings are reported, not hidden,
but do not change the exit code), 1 = scan error.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys

CVE = "CVE-2026-111497"
ALSO_KNOWN_AS = ["Node2Shell", "HTTP2Shell", "Broccoli2Shell"]

# Node.js October 2026 security release: fixed patch per supported line.
NODE_FIXED = {22: (22, 23, 4), 24: (24, 22, 1), 26: (26, 12, 1)}
# Lines with no fix at all: 20.x and older are end of life, 23.x and 25.x
# are end of life too. Anything newer than 26.x is UNKNOWN, the advisory
# does not speak about it yet.
BUN_FIXED = (1, 4, 4)
# Brotli library fixes per release line (Google Brotli releases).
BROTLI_FIXED = {(1, 0): (1, 0, 10), (1, 1): (1, 1, 1), (1, 2): (1, 2, 1)}
BROTLICFFI_FIXED = (1, 2, 1, 0)

_VERSION_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:\.(\d+))?(?:[-+].*)?$")


def parse_version(text):
    """Parse a version string into a tuple of ints, or None.

    Accepts a leading 'v' and an optional fourth component (brotlicffi
    uses four, e.g. 1.2.1.0). Anything with trailing junk that is not a
    pre-release/build suffix is rejected rather than guessed at.
    """
    if text is None:
        return None
    text = text.strip()
    if not text:
        return None
    match = _VERSION_RE.match(text)
    if not match:
        return None
    parts = [int(g) for g in match.groups() if g is not None]
    return tuple(parts)


def _cmp(version, fixed):
    """Compare version tuples of different lengths on equal footing."""
    length = max(len(version), len(fixed))
    left = version + (0,) * (length - len(version))
    right = fixed + (0,) * (length - len(fixed))
    return (left > right) - (left < right)


def grade_node(version_text):
    """Grade a Node.js version string. Returns (verdict, version, detail)."""
    version = parse_version(version_text)
    if version is None or len(version) < 3:
        return ("UNKNOWN", None,
                "unparseable Node.js version string: %r" % (version_text or "")[:80])
    major = version[0]
    shown = ".".join(str(p) for p in version[:3])
    if major in NODE_FIXED:
        fixed = NODE_FIXED[major]
        if _cmp(version[:3], fixed) < 0:
            return ("VULNERABLE", shown,
                    "Node.js %s predates the fix (%s); upgrade to %s or later"
                    % (shown, ".".join(str(p) for p in fixed),
                       ".".join(str(p) for p in fixed)))
        return ("FIXED", shown,
                "Node.js %s is at or past the fixed release for the %s.x line"
                % (shown, major))
    if major > 26:
        return ("UNKNOWN", shown,
                "Node.js %s.x is newer than the lines the October 2026 advisory "
                "covers; confirm against the current advisory" % major)
    return ("EOL_NO_FIX", shown,
            "Node.js %s.x is end of life and will never receive this fix; "
            "move to 22.x, 24.x or 26.x at a fixed patch" % major)


def grade_bun(version_text):
    """Grade a Bun version string. Returns (verdict, version, detail)."""
    version = parse_version(version_text)
    if version is None or len(version) < 3:
        return ("UNKNOWN", None,
                "unparseable Bun version string: %r" % (version_text or "")[:80])
    shown = ".".join(str(p) for p in version[:3])
    if _cmp(version[:3], BUN_FIXED) < 0:
        return ("VULNERABLE", shown,
                "Bun %s predates 1.4.4, which carries the Brotli fix; upgrade "
                "to 1.4.4 or later" % shown)
    return ("FIXED", shown, "Bun %s is at or past 1.4.4" % shown)


def grade_brotli(version_text):
    """Grade a Google Brotli library version. Returns (verdict, version, detail)."""
    version = parse_version(version_text)
    if version is None or len(version) < 3:
        return ("UNKNOWN", None,
                "unparseable Brotli version string: %r" % (version_text or "")[:80])
    shown = ".".join(str(p) for p in version[:3])
    branch = version[:2]
    if branch in BROTLI_FIXED and _cmp(version[:3], BROTLI_FIXED[branch]) >= 0:
        return ("FIXED", shown,
                "Brotli %s is at or past the fixed release for the %s line"
                % (shown, ".".join(str(p) for p in branch)))
    if version[:3] >= (1, 2, 1):
        return ("FIXED", shown, "Brotli %s is past the 1.2.1 fix" % shown)
    if (1, 0, 3) <= version[:3] <= (1, 2, 0):
        return ("VULNERABLE", shown,
                "Brotli %s is inside the affected range 1.0.3 through 1.2.0; "
                "upgrade to 1.0.10, 1.1.1 or 1.2.1 for your line" % shown)
    return ("UNKNOWN", shown,
            "Brotli %s is outside the CVE record's stated range 1.0.3-1.2.0 "
            "and is not a known fixed release; confirm against the Brotli "
            "advisory" % shown)


def grade_brotlicffi(version_text):
    """Grade a brotlicffi version (four components). Returns (verdict, version, detail)."""
    version = parse_version(version_text)
    if version is None:
        return ("UNKNOWN", None,
                "unparseable brotlicffi version string: %r" % (version_text or "")[:80])
    shown = ".".join(str(p) for p in version)
    if _cmp(version, BROTLICFFI_FIXED) < 0:
        return ("VULNERABLE", shown,
                "brotlicffi %s predates 1.2.1.0; upgrade to 1.2.1.0 or later" % shown)
    return ("FIXED", shown, "brotlicffi %s is at or past 1.2.1.0" % shown)


def run_version(binary, args=("--version",)):
    """Run a binary with --version. Returns its stdout, or None on failure."""
    try:
        proc = subprocess.run([binary, *args], capture_output=True, text=True,
                              timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    line = proc.stdout.strip().splitlines()
    return line[0].strip() if line else None


def binary_findings(scan_dirs, include_path=True):
    """Find node/bun binaries and grade them. Returns a list of findings."""
    findings = []
    seen = set()
    candidates = []
    if include_path:
        for name in ("node", "bun"):
            path = shutil.which(name)
            if path:
                candidates.append((name, path))
    for scan_dir in scan_dirs:
        for root, dirs, _files in os.walk(scan_dir):
            dirs[:] = [d for d in dirs if d not in (".git", "node_modules")]
            for name in ("node", "bun"):
                path = os.path.join(root, name)
                if os.path.isfile(path) and os.access(path, os.X_OK):
                    candidates.append((name, path))
    for name, path in candidates:
        real = os.path.realpath(path)
        if real in seen:
            continue
        seen.add(real)
        raw = run_version(path)
        grader = grade_node if name == "node" else grade_bun
        verdict, version, detail = grader(raw)
        if name == "node" and path.startswith(("/usr/bin/", "/usr/lib/")):
            detail = detail.rstrip()
            if not detail.endswith("."):
                detail += "."
            detail += (" Note: a distribution-packaged Node.js may use the "
                       "system Brotli library instead of the bundled copy, "
                       "so check the distribution brotli package too.")
        findings.append({"kind": name, "source": path, "version": version,
                         "verdict": verdict, "detail": detail})
    return findings


def python_package_findings():
    """Grade installed brotli / brotlicffi in this interpreter's environment."""
    findings = []
    try:
        from importlib import metadata as importlib_metadata
    except ImportError:  # pragma: no cover - Python 2 has no such module
        return findings
    graders = {"brotli": grade_brotli, "brotlicffi": grade_brotlicffi}
    for dist in importlib_metadata.distributions():
        name = (dist.metadata["Name"] or "").lower()
        if name in graders:
            verdict, version, detail = graders[name](dist.version)
            findings.append({"kind": "python-%s" % name, "source": name,
                             "version": version, "verdict": verdict,
                             "detail": detail})
    return findings


_DOCKER_FROM_RE = re.compile(r"^FROM\s+(?:--\S+\s+)*node:([^\s]+)", re.IGNORECASE)


def grade_docker_tag(tag):
    """Grade a node: Docker tag. Returns (verdict, version_or_None, detail)."""
    base = tag.split("@")[0]
    version_part = base.split("-")[0]
    if version_part in ("latest", "") or version_part.count(".") == 0:
        return ("UNKNOWN", None,
                "node:%s is a floating tag; rebuild with --pull and verify "
                "the running version, it may still be a pre-fix patch" % tag)
    version = parse_version(version_part)
    if version is None or len(version) < 3:
        if version_part.count(".") in (1, 2):
            return ("UNKNOWN", None,
                    "node:%s pins a line, not a patch; rebuild with --pull "
                    "and verify the running version" % tag)
        return ("UNKNOWN", None, "unparseable node tag: node:%s" % tag)
    verdict, shown, detail = grade_node(version_part)
    return (verdict, shown, "Docker base image node:%s -> %s" % (tag, detail))


def _major_of(spec):
    """Best-effort major version from an npm spec like ^5.3.0, or None."""
    match = re.search(r"(\d+)", spec or "")
    return int(match.group(1)) if match else None


def project_findings(scan_dirs):
    """Scan project trees for pins, engines and body-parser exposure notes."""
    findings = []
    for scan_dir in scan_dirs:
        for root, dirs, files in os.walk(scan_dir):
            dirs[:] = [d for d in dirs if d not in (".git", "node_modules")]
            if ".nvmrc" in files:
                path = os.path.join(root, ".nvmrc")
                try:
                    with open(path, encoding="utf-8", errors="replace") as handle:
                        raw = handle.read().strip().splitlines()[0].strip()
                except OSError:
                    raw = ""
                verdict, version, detail = grade_node(raw)
                findings.append({"kind": "nvmrc", "source": path,
                                 "version": version, "verdict": verdict,
                                 "detail": detail})
            if "package.json" in files:
                path = os.path.join(root, "package.json")
                try:
                    with open(path, encoding="utf-8", errors="replace") as handle:
                        data = json.load(handle)
                except (OSError, ValueError):
                    continue
                notes = []
                engines = (data.get("engines") or {}).get("node")
                if engines:
                    notes.append("engines.node is %s" % engines)
                deps = {}
                deps.update(data.get("dependencies") or {})
                deps.update(data.get("devDependencies") or {})
                if _major_of(deps.get("express")) == 5:
                    notes.append("Express 5 decodes Brotli request bodies by "
                                 "default, so attacker-controlled bodies reach "
                                 "the bundled decoder")
                if _major_of(deps.get("body-parser")) == 2:
                    notes.append("body-parser 2.x decodes Brotli request "
                                 "bodies by default")
                if notes:
                    findings.append({"kind": "project", "source": path,
                                     "version": None, "verdict": "INFO",
                                     "detail": "; ".join(notes)})
            for filename in files:
                if filename == "Dockerfile" or filename.startswith("Dockerfile."):
                    path = os.path.join(root, filename)
                    try:
                        with open(path, encoding="utf-8",
                                  errors="replace") as handle:
                            lines = handle.read().splitlines()
                    except OSError:
                        continue
                    for line in lines:
                        match = _DOCKER_FROM_RE.match(line.strip())
                        if match:
                            verdict, version, detail = grade_docker_tag(match.group(1))
                            findings.append({"kind": "dockerfile",
                                             "source": path, "version": version,
                                             "verdict": verdict, "detail": detail})
    return findings


def scan(scan_dirs=(), include_path=True, project_dirs=None,
         include_python=True):
    """Run the full inventory. Returns (result_dict, exit_code)."""
    if project_dirs is None:
        project_dirs = list(scan_dirs) if scan_dirs else [os.getcwd()]
    findings = []
    findings.extend(binary_findings(list(scan_dirs), include_path))
    if include_python:
        findings.extend(python_package_findings())
    findings.extend(project_findings(project_dirs))
    summary = {}
    for finding in findings:
        summary[finding["verdict"]] = summary.get(finding["verdict"], 0) + 1
    if summary.get("VULNERABLE") or summary.get("EOL_NO_FIX"):
        overall, code = "VULNERABLE", 2
    elif summary.get("UNKNOWN"):
        overall, code = "UNKNOWN", 0
    elif findings:
        overall, code = "CLEAN", 0
    else:
        overall, code = "CLEAN", 0
    return ({"cve": CVE, "verdict": overall, "summary": summary,
             "findings": findings}, code)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Local inventory triage for CVE-2026-111497 (Node2Shell). "
                    "No network access, no payloads.")
    parser.add_argument("--scan-dir", action="append", default=[],
                        help="tree to scan for node/bun binaries and project "
                             "files (repeatable)")
    parser.add_argument("--no-path", action="store_true",
                        help="do not include node/bun found on PATH")
    parser.add_argument("--json", action="store_true",
                        help="machine-readable output")
    args = parser.parse_args(argv)

    for scan_dir in args.scan_dir:
        if not os.path.isdir(scan_dir):
            print("error: not a directory: %s" % scan_dir, file=sys.stderr)
            return 1
    result, code = scan(args.scan_dir, include_path=not args.no_path)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("cve:     %s (%s)" % (CVE, ", ".join(ALSO_KNOWN_AS)))
        print("verdict: %s" % result["verdict"])
        print("summary: %s" % json.dumps(result["summary"]))
        for finding in result["findings"]:
            print("- [%s] %s %s: %s"
                  % (finding["verdict"], finding["kind"], finding["source"],
                     finding["detail"]))
        if not result["findings"]:
            print("no node, bun, brotli, or project files found in scope")
        if result["verdict"] == "UNKNOWN":
            print("note: UNKNOWN is not clean. Confirm those items another way.")
    return code


if __name__ == "__main__":
    sys.exit(main())
