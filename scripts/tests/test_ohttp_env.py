# Copyright © 2026 Znewco, Inc. (d/b/a Zcash Open Development Lab)
# SPDX-License-Identifier: AGPL-3.0-only
#
# This file is part of ZODL Slipstream.
#
# ZODL Slipstream is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License,
# version 3 only, as published by the Free Software Foundation.
#
# ZODL Slipstream is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Affero General Public License for more details.
#
# Commercial licensing: see COMMERCIAL-LICENSE.md.

"""CI configuration is required, inherited, private and cache-bound."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

RUNNER = Path(__file__).resolve().parents[1] / "ci/ohttp_env.py"
MATRIX = Path(__file__).resolve().with_name("ohttp_configuration.py")
NAMES = tuple("ZODL_OHTTP_" + suffix for suffix in (
    "GATEWAY_HOST_MAINNET", "GATEWAY_HOST_TESTNET", "RELAY_URL_MAINNET", "RELAY_URL_TESTNET",
    "SIGNING_PUBKEY_MAINNET", "SIGNING_PUBKEY_TESTNET", "KEYS_DNS_NAME_MAINNET", "KEYS_DNS_NAME_TESTNET"))
VALUES = dict(zip(NAMES, (
    "main.example.invalid", "test.example.invalid", "https://main.example.invalid/relay",
    "https://test.example.invalid/relay", "a" * 64, "b" * 64,
    "main.keys.example.invalid", "test.keys.example.invalid")))
EXPECTED = "4a40b1994934a0e6920e8e293a590848dcbd83978ed2ac2facec55e0b1cea438"


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(RUNNER.is_file(), "CI configuration helper is missing")
        spec = importlib.util.spec_from_file_location("ci_ohttp_env", RUNNER)
        self.runner = importlib.util.module_from_spec(spec)
        with patch("subprocess.Popen", side_effect=AssertionError("configuration acquisition forbidden")), \
                patch("os.system", side_effect=AssertionError("shell acquisition forbidden")):
            spec.loader.exec_module(self.runner)

    def test_each_absent_or_empty_input_is_rejected_without_values(self):
        for name in NAMES:
            for empty in (False, True):
                values = dict(VALUES, CANARY="private-canary-value")
                if empty:
                    values[name] = ""
                else:
                    del values[name]
                with self.subTest(name=name, empty=empty):
                    with self.assertRaises(ValueError) as failure:
                        self.runner.validate_configuration(values)
                    self.assertIn(name, str(failure.exception))
                    for value in values.values():
                        if value:
                            self.assertNotIn(value, str(failure.exception))
                    with self.assertRaises(ValueError):
                        self.runner.configuration_hash(values)

    def test_complete_inherited_values_are_preserved_without_acquisition(self):
        values = dict(VALUES, OTHER="untouched")
        before = dict(values)
        with patch("subprocess.Popen", side_effect=AssertionError("configuration acquisition forbidden")), \
                patch("os.system", side_effect=AssertionError("shell acquisition forbidden")):
            self.assertIsNone(self.runner.validate_configuration(values))
            self.assertEqual(self.runner.configuration_hash(values), EXPECTED)
        self.assertEqual(values, before)

    def test_corresponding_network_values_must_differ_ignoring_ascii_case(self):
        for first, second in ((0, 1), (2, 3), (4, 5), (6, 7)):
            for case_only in (False, True):
                values = dict(VALUES)
                matching = values[NAMES[first]]
                if case_only:
                    matching = matching.upper().replace("HTTPS://", "https://", 1)
                values[NAMES[second]] = matching
                with self.subTest(name=NAMES[second], case_only=case_only):
                    with self.assertRaises(ValueError) as failure:
                        self.runner.configuration_hash(values)
                    self.assertIn(NAMES[first], str(failure.exception))
                    self.assertIn(NAMES[second], str(failure.exception))
                    for value in values.values():
                        self.assertNotIn(value, str(failure.exception))

    def test_malformed_inputs_are_rejected_without_values(self):
        bad_hosts = ("é.example", "host.example.", "-host.example", "host..example",
                     "a" * 64 + ".example", "a." * 127 + "a", "host:443", "https://host.example")
        bad_relays = ("http://relay.example", "https://", "https://user@relay.example",
                      "https://relay.example/white space", "https://relay.example/\x00")
        bad_keys = ("a" * 63, "g" * 64, "é" * 64)
        for name in NAMES:
            if "SIGNING_PUBKEY" in name:
                malformed = bad_keys
            elif "RELAY_URL" in name:
                malformed = bad_relays
            else:
                malformed = bad_hosts
            for value in malformed:
                values = dict(VALUES)
                values[name] = value
                with self.subTest(name=name, value=value):
                    with self.assertRaises(ValueError) as failure:
                        self.runner.configuration_hash(values)
                    self.assertIn(name, str(failure.exception))
                    self.assertNotIn(value, str(failure.exception))

    def test_valid_case_and_url_spelling_are_preserved(self):
        values = {name: value.upper() if "RELAY_URL" not in name else value for name, value in VALUES.items()}
        before = dict(values)
        self.assertIsNone(self.runner.validate_configuration(values))
        self.assertNotEqual(self.runner.configuration_hash(values), EXPECTED)
        self.assertEqual(values, before)
        for relay in ("https://relay.example:8443/path?query=value", "https://[::1]/relay"):
            values = dict(VALUES, ZODL_OHTTP_RELAY_URL_MAINNET=relay)
            self.assertIsNone(self.runner.validate_configuration(values))

    def test_digest_preserves_utf8_bytes_and_excludes_build_policy(self):
        values = dict(VALUES, ZODL_OHTTP_RELAY_URL_MAINNET="https://main.example.invalid/relây")
        self.assertEqual(self.runner.configuration_hash(values),
                         "5bb7495555789759a9f5dd299d1b8b38417b2b79741a2096dfa9c07ef3186a02")
        self.assertEqual(values["ZODL_OHTTP_RELAY_URL_MAINNET"], "https://main.example.invalid/relây")
        self.assertEqual(self.runner.configuration_hash(dict(VALUES, ZODL_OHTTP_REQUIRE="1")), EXPECTED)

    def test_digest_uses_fixed_order_and_each_original_value(self):
        self.assertEqual(self.runner.configuration_hash(dict(reversed(list(VALUES.items())))), EXPECTED)
        for name in NAMES:
            changed = dict(VALUES)
            if "SIGNING_PUBKEY" in name:
                changed[name] = "c" * 64
            elif "RELAY_URL" in name:
                changed[name] += "/changed"
            else:
                changed[name] = "changed." + changed[name]
            with self.subTest(name=name):
                self.assertNotEqual(self.runner.configuration_hash(changed), EXPECTED)

    def test_cli_requires_inputs_and_never_acquires_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "acquisition-attempt"
            for command in ("gh", "aws", "op", "security", "zsh", "bash", "sh", "curl"):
                executable = root / command
                executable.write_text(f"#!/bin/sh\necho attempted > '{marker}'\nexit 97\n")
                executable.chmod(0o755)
            env = dict(VALUES, PATH=directory, HOME=directory)
            result = subprocess.run([sys.executable, "-B", str(RUNNER), "--hash"], env=env,
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, EXPECTED + "\n")
            self.assertEqual(result.stderr, "")
            for name in NAMES:
                for empty in (False, True):
                    missing = dict(env, CANARY="private-canary-value")
                    if empty:
                        missing[name] = ""
                    else:
                        del missing[name]
                    result = subprocess.run([sys.executable, "-B", str(RUNNER), "--hash"],
                                            env=missing, capture_output=True, text=True)
                    with self.subTest(name=name, empty=empty):
                        self.assertNotEqual(result.returncode, 0)
                        self.assertEqual(result.stdout, "")
                        self.assertIn(name, result.stderr)
                        self.assertNotIn("private-canary-value", result.stderr)
                        for value in VALUES.values():
                            self.assertNotIn(value, result.stderr)
            self.assertFalse(marker.exists(), "CLI attempted configuration acquisition")


class MatrixDiagnosticsTests(unittest.TestCase):
    def run_matrix_with_cargo_output(self, case, output, returncode):
        with tempfile.TemporaryDirectory() as directory:
            cargo = Path(directory) / "cargo"
            cargo.write_text(f"#!{sys.executable}\nimport sys\nsys.stderr.write({output!r})\nsys.exit({returncode})\n")
            cargo.chmod(0o755)
            return subprocess.run([sys.executable, "-B", str(MATRIX), case],
                                  env={"PATH": directory}, capture_output=True, text=True)

    def test_rerun_metadata_does_not_establish_the_rejected_variable(self):
        output = ("failed to run custom build command for `zodl-ohttp-client v0.1.2`\n"
                  "--- stdout\n" + "\n".join("cargo:rerun-if-env-changed=" + name for name in NAMES)
                  + "\n--- stderr\ninvalid OHTTP build configuration:\n"
                  "ZODL_OHTTP_REQUIRE must be 1, 0 or unset\n")
        result = self.run_matrix_with_cargo_output("no-dns", output, 101)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("expected core build rejection", result.stdout)

    def test_success_without_running_the_contract_is_rejected(self):
        result = self.run_matrix_with_cargo_output(
            "complete", "test result: ok. 0 passed; 0 failed; 1 filtered out\n", 0)
        self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_expected_core_diagnostic_is_accepted(self):
        output = ("failed to run custom build command for `zodl-ohttp-client v0.1.2`\n"
                  "--- stderr\ninvalid OHTTP build configuration:\n"
                  "ZODL_OHTTP_KEYS_DNS_NAME_TESTNET missing\n")
        result = self.run_matrix_with_cargo_output("no-dns", output, 101)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
