"""Tests for node2shell_inventory_scanner. Hermetic: fake binaries and
fake project trees only, no network, no real runtimes, no payloads."""

import json
import os
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import node2shell_inventory_scanner as scanner


def make_binary(directory, name, output):
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("#!/bin/sh\nprintf '%s\\n' '%s'\n" % ("%s", output))
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


class GradeNodeTests(unittest.TestCase):
    def test_vulnerable_patches(self):
        for version in ("v22.23.3", "24.22.0", "26.12.0"):
            verdict, _, _ = scanner.grade_node(version)
            self.assertEqual(verdict, "VULNERABLE", version)

    def test_fixed_patches(self):
        for version in ("v22.23.4", "24.22.1", "26.12.1", "24.22.5"):
            verdict, _, _ = scanner.grade_node(version)
            self.assertEqual(verdict, "FIXED", version)

    def test_eol_lines_have_no_fix(self):
        for version in ("20.19.5", "23.11.0", "25.0.0", "18.20.0"):
            verdict, _, _ = scanner.grade_node(version)
            self.assertEqual(verdict, "EOL_NO_FIX", version)

    def test_unknown_newer_line(self):
        verdict, _, _ = scanner.grade_node("27.0.0")
        self.assertEqual(verdict, "UNKNOWN")

    def test_unparseable(self):
        verdict, version, _ = scanner.grade_node("not-a-version")
        self.assertEqual((verdict, version), ("UNKNOWN", None))


class GradeBunAndBrotliTests(unittest.TestCase):
    def test_bun(self):
        self.assertEqual(scanner.grade_bun("1.4.3")[0], "VULNERABLE")
        self.assertEqual(scanner.grade_bun("1.4.4")[0], "FIXED")
        self.assertEqual(scanner.grade_bun("1.5.0")[0], "FIXED")

    def test_brotli_branches(self):
        self.assertEqual(scanner.grade_brotli("1.0.9")[0], "VULNERABLE")
        self.assertEqual(scanner.grade_brotli("1.0.10")[0], "FIXED")
        self.assertEqual(scanner.grade_brotli("1.1.0")[0], "VULNERABLE")
        self.assertEqual(scanner.grade_brotli("1.1.1")[0], "FIXED")
        self.assertEqual(scanner.grade_brotli("1.2.0")[0], "VULNERABLE")
        self.assertEqual(scanner.grade_brotli("1.2.1")[0], "FIXED")

    def test_brotli_outside_range_is_unknown(self):
        self.assertEqual(scanner.grade_brotli("1.0.2")[0], "UNKNOWN")

    def test_brotlicffi(self):
        self.assertEqual(scanner.grade_brotlicffi("1.2.0.0")[0], "VULNERABLE")
        self.assertEqual(scanner.grade_brotlicffi("1.2.1.0")[0], "FIXED")


class InventoryTests(unittest.TestCase):
    def test_fake_binaries_graded(self):
        with tempfile.TemporaryDirectory() as tmp:
            make_binary(tmp, "node", "v24.22.0")
            make_binary(tmp, "bun", "1.4.3")
            result, code = scanner.scan([tmp], include_path=False,
                                        project_dirs=[], include_python=False)
            by_kind = {f["kind"]: f for f in result["findings"]}
            self.assertEqual(by_kind["node"]["verdict"], "VULNERABLE")
            self.assertEqual(by_kind["bun"]["verdict"], "VULNERABLE")
            self.assertEqual(code, 2)

    def test_fixed_binaries_are_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            make_binary(tmp, "node", "v24.22.1")
            result, code = scanner.scan([tmp], include_path=False,
                                        project_dirs=[], include_python=False)
            self.assertEqual(result["verdict"], "CLEAN")
            self.assertEqual(code, 0)

    def test_project_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, ".nvmrc"), "w") as handle:
                handle.write("22.23.3\n")
            with open(os.path.join(tmp, "package.json"), "w") as handle:
                json.dump({"dependencies": {"express": "^5.3.0"},
                           "engines": {"node": ">=22"}}, handle)
            with open(os.path.join(tmp, "Dockerfile"), "w") as handle:
                handle.write("FROM node:24.22.0-slim\n")
            with open(os.path.join(tmp, "Dockerfile.pinned"), "w") as handle:
                handle.write("FROM node:24\n")
            result, code = scanner.scan([], include_path=False,
                                        project_dirs=[tmp],
                                        include_python=False)
            by_source = {}
            for finding in result["findings"]:
                by_source.setdefault(finding["source"], []).append(finding)
            nvmrc = [f for f in by_source[os.path.join(tmp, ".nvmrc")]]
            self.assertEqual(nvmrc[0]["verdict"], "VULNERABLE")
            project = [f for f in by_source[os.path.join(tmp, "package.json")]]
            self.assertEqual(project[0]["verdict"], "INFO")
            self.assertIn("Express 5", project[0]["detail"])
            docker = [f for f in by_source[os.path.join(tmp, "Dockerfile")]]
            self.assertEqual(docker[0]["verdict"], "VULNERABLE")
            floating = [f for f in by_source[os.path.join(tmp, "Dockerfile.pinned")]]
            self.assertEqual(floating[0]["verdict"], "UNKNOWN")
            self.assertEqual(code, 2)

    def test_duplicate_binaries_deduplicated(self):
        with tempfile.TemporaryDirectory() as tmp:
            make_binary(tmp, "node", "v22.23.3")
            sub = os.path.join(tmp, "sub")
            os.mkdir(sub)
            os.symlink(os.path.join(tmp, "node"), os.path.join(sub, "node"))
            findings = scanner.binary_findings([tmp], include_path=False)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["verdict"], "VULNERABLE")


class DockerTagTests(unittest.TestCase):
    def test_floating_tag_unknown(self):
        self.assertEqual(scanner.grade_docker_tag("latest")[0], "UNKNOWN")
        self.assertEqual(scanner.grade_docker_tag("24")[0], "UNKNOWN")

    def test_fixed_tag(self):
        verdict, version, _ = scanner.grade_docker_tag("24.22.1-alpine")
        self.assertEqual((verdict, version), ("FIXED", "24.22.1"))


if __name__ == "__main__":
    unittest.main()
