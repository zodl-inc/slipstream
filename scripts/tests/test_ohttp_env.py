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

    def test_matching_relay_key_and_dns_are_allowed(self):
        values = dict(VALUES)
        for kind in ("RELAY_URL", "SIGNING_PUBKEY", "KEYS_DNS_NAME"):
            values[f"ZODL_OHTTP_{kind}_TESTNET"] = values[f"ZODL_OHTTP_{kind}_MAINNET"]
        self.assertIsNone(self.runner.validate_configuration(values))
        self.assertEqual(len(self.runner.configuration_hash(values)), 64)

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
        # Byte lengths must count UTF-8 bytes, and presence validation does not own format.
        unicode_values = dict(VALUES, ZODL_OHTTP_KEYS_DNS_NAME_MAINNET="é.example")
        self.assertIsNone(self.runner.validate_configuration(unicode_values))
        self.assertNotEqual(self.runner.configuration_hash(unicode_values), EXPECTED)

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


if __name__ == "__main__":
    unittest.main()
