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


def environment(case):
    env = {key: value for key, value in os.environ.items() if key not in NAMES}
    env.update(FIXTURES)
    env["SLIPSTREAM_TEST_CONFIGURATION"] = "complete" if case == "mixed-case" else case
    if case == "mixed-case":
        env["ZODL_OHTTP_GATEWAY_HOST_MAINNET"] = "Main-With-Testnet-In-Name.Example"
        env["ZODL_OHTTP_GATEWAY_HOST_TESTNET"] = "Alternate-Chain.Example"
    if case in ("ambiguous-hosts", "ambiguous-partial-mainnet"):
        env["ZODL_OHTTP_GATEWAY_HOST_MAINNET"] = "Shared-Gateway.Example"
        env["ZODL_OHTTP_GATEWAY_HOST_TESTNET"] = "shared-gateway.example"
    if case == "ambiguous-partial-mainnet":
        del env["ZODL_OHTTP_SIGNING_PUBKEY_MAINNET"]
    if case == "no-dns":
        del env["ZODL_OHTTP_KEYS_DNS_NAME_TESTNET"]
    if case == "no-signing":
        del env["ZODL_OHTTP_SIGNING_PUBKEY_TESTNET"]
    return env


def main():
    if sys.argv[1:2] == ["--"]:
        if len(sys.argv) < 3:
            raise SystemExit("provide a command after --")
        result = subprocess.run(sys.argv[2:], cwd=ROOT, env=environment("complete"))
        raise SystemExit(result.returncode)
    for case in sys.argv[1:] or ["complete", "no-dns", "no-signing", "mixed-case", "ambiguous-hosts", "ambiguous-partial-mainnet"]:
        if case not in ("complete", "no-dns", "no-signing", "mixed-case", "ambiguous-hosts", "ambiguous-partial-mainnet"):
            raise SystemExit("unknown configuration case")
        print("OHTTP configuration case:", case, flush=True)
        subprocess.run([
            "cargo", "test", "--locked", "--offline", "-p", "zodl-slipstream",
            "--lib", "ohttp::tests::compiled_configuration_contract", "--", "--exact",
        ], cwd=ROOT, env=environment(case), check=True)


if __name__ == "__main__":
    main()
