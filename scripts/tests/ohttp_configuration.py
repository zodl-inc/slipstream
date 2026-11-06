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

"""Exercise the real compile-time OHTTP inputs using public, offline fixtures."""
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
NAMES = [
    "ZODL_OHTTP_GATEWAY_HOST_MAINNET", "ZODL_OHTTP_GATEWAY_HOST_TESTNET",
    "ZODL_OHTTP_RELAY_URL_MAINNET", "ZODL_OHTTP_RELAY_URL_TESTNET",
    "ZODL_OHTTP_SIGNING_PUBKEY_MAINNET", "ZODL_OHTTP_SIGNING_PUBKEY_TESTNET",
    "ZODL_OHTTP_KEYS_DNS_NAME_MAINNET", "ZODL_OHTTP_KEYS_DNS_NAME_TESTNET",
]
FIXTURES = dict(zip(NAMES, [
    # Deliberately reverse the heuristic: network comes from configuration.
    "main-with-testnet-in-name.example", "alternate-chain.example",
    "https://relay-mainnet.example/relay", "https://relay-testnet.example/relay",
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0",
    "mainnet.ohttp-keys.example", "testnet.ohttp-keys.example",
]))


POSITIVE_CASES = ("complete", "mixed-case", "none", "mainnet-only", "testnet-only")
FAILURE_CASES = {
    "strict-none": tuple(NAMES),
    "strict-mainnet-only": tuple(name for name in NAMES if name.endswith("TESTNET")),
    "strict-testnet-only": tuple(name for name in NAMES if name.endswith("MAINNET")),
    "no-dns": (NAMES[7],),
    "no-signing": (NAMES[5],),
    "ambiguous-hosts": (NAMES[0], NAMES[1]),
    "ambiguous-partial-mainnet": (NAMES[4],),
    "ambiguous-partial-mainnet-identical": (NAMES[4],),
}
for name in NAMES:
    FAILURE_CASES["partial-" + name] = (name,)
    FAILURE_CASES["strict-missing-" + name] = (name,)
for first, second in zip(NAMES[::2], NAMES[1::2]):
    for spelling in ("identical", "case-only"):
        FAILURE_CASES["duplicate-" + spelling + "-" + first] = (first, second)


def environment(case):
    # Never allow inherited deployment configuration or strict policy into fixtures.
    env = {key: value for key, value in os.environ.items() if not key.startswith("ZODL_OHTTP_")}
    env.update(FIXTURES)
    if case in ("complete", "mixed-case"):
        env["ZODL_OHTTP_REQUIRE"] = "1"
    if case in ("strict-none", "strict-mainnet-only", "strict-testnet-only"):
        env["ZODL_OHTTP_REQUIRE"] = "1"
        case = case.removeprefix("strict-")
    env["SLIPSTREAM_TEST_CONFIGURATION"] = "complete" if case == "mixed-case" else case
    if case == "mixed-case":
        env[NAMES[0]] = "Main-With-Testnet-In-Name.Example"
        env[NAMES[1]] = "Alternate-Chain.Example"
    if case == "none":
        for name in NAMES:
            del env[name]
    if case in ("mainnet-only", "testnet-only"):
        absent_network = "TESTNET" if case == "mainnet-only" else "MAINNET"
        for name in NAMES:
            if name.endswith(absent_network):
                del env[name]
    if case in ("ambiguous-hosts", "ambiguous-partial-mainnet", "ambiguous-partial-mainnet-identical"):
        env[NAMES[0]] = "Shared-Gateway.Example"
        env[NAMES[1]] = "Shared-Gateway.Example" if case.endswith("identical") else "shared-gateway.example"
    if case.startswith("ambiguous-partial-mainnet"):
        del env[NAMES[4]]
    if case == "no-dns":
        del env[NAMES[7]]
    if case == "no-signing":
        del env[NAMES[5]]
    if case.startswith("partial-"):
        del env[case.removeprefix("partial-")]
    if case.startswith("strict-missing-"):
        env["ZODL_OHTTP_REQUIRE"] = "1"
        del env[case.removeprefix("strict-missing-")]
    if case.startswith("duplicate-"):
        first, second = FAILURE_CASES[case]
        env[second] = env[first].upper().replace("HTTPS://", "https://", 1) if case.startswith("duplicate-case-only-") else env[first]
    return env


def main():
    if sys.argv[1:2] == ["--"]:
        if len(sys.argv) < 3:
            raise SystemExit("provide a command after --")
        result = subprocess.run(sys.argv[2:], cwd=ROOT, env=environment("complete"))
        raise SystemExit(result.returncode)
    failed = []
    for case in sys.argv[1:] or [*POSITIVE_CASES, *FAILURE_CASES]:
        if case not in POSITIVE_CASES and case not in FAILURE_CASES:
            raise SystemExit("unknown configuration case")
        print("OHTTP configuration case:", case, flush=True)
        command = ["cargo", "check" if case in FAILURE_CASES else "test",
                   "--locked", "--offline", "-p", "zodl-slipstream", "--lib"]
        if case not in FAILURE_CASES:
            command += ["ohttp::tests::compiled_configuration_contract", "--", "--exact"]
        case_env = environment(case)
        result = subprocess.run(command, cwd=ROOT, env=case_env, capture_output=True, text=True)
        output = result.stdout + result.stderr
        fixture_values = [value for name, value in case_env.items() if name in NAMES]
        if any(value in output or value.upper() in output or value.lower() in output for value in fixture_values):
            failed.append(case)
            print("FAIL: Cargo diagnostics exposed a configuration fixture", flush=True)
            continue
        if case in FAILURE_CASES:
            expected = FAILURE_CASES[case]
            # Compiler/network errors are not evidence that configuration was rejected.
            problems = output.partition("--- stderr")[2].partition("invalid OHTTP build configuration:")[2]
            rejected = result.returncode != 0 and "failed to run custom build command for `zodl-ohttp-client" in output
            if not rejected or not problems or not all(name in problems for name in expected):
                failed.append(case)
                print("FAIL: expected core build rejection naming " + ", ".join(expected) + f" (Cargo exit {result.returncode})", flush=True)
            else:
                print("PASS: core rejected " + ", ".join(expected), flush=True)
        elif result.returncode or "test result: ok. 1 passed;" not in output:
            failed.append(case)
            # Cargo output can include fixture values; diagnostics stay value-free.
            print("FAIL: positive configuration did not compile and pass", flush=True)
        else:
            print("PASS: compiled configuration contract", flush=True)
    if failed:
        raise SystemExit("Configuration cases failed: " + ", ".join(failed))


if __name__ == "__main__":
    main()
