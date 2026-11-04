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

"""Require CI's inherited OHTTP inputs and bind caches to their original values.

Only presence is checked here. The native core owns input format validation.
"""
import argparse
from collections.abc import Mapping
import hashlib
import os
import sys

OHTTP_NAMES = (
    "ZODL_OHTTP_GATEWAY_HOST_MAINNET",
    "ZODL_OHTTP_GATEWAY_HOST_TESTNET",
    "ZODL_OHTTP_RELAY_URL_MAINNET",
    "ZODL_OHTTP_RELAY_URL_TESTNET",
    "ZODL_OHTTP_SIGNING_PUBKEY_MAINNET",
    "ZODL_OHTTP_SIGNING_PUBKEY_TESTNET",
    "ZODL_OHTTP_KEYS_DNS_NAME_MAINNET",
    "ZODL_OHTTP_KEYS_DNS_NAME_TESTNET",
)


def validate_configuration(environ: Mapping[str, str]) -> None:
    missing = [name for name in OHTTP_NAMES if not environ.get(name)]
    if missing:
        raise ValueError("Missing required OHTTP configuration: " + ", ".join(missing))


def configuration_hash(environ: Mapping[str, str]) -> str:
    validate_configuration(environ)
    digest = hashlib.sha256(b"ZODL-OHTTP-CONFIG\x00v1\x00")
    for name in OHTTP_NAMES:
        for field in (name, environ[name]):
            encoded = field.encode("utf-8")
            digest.update(len(encoded).to_bytes(8, "big"))
            digest.update(encoded)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hash", action="store_true", required=True,
                        help="Print the validated configuration digest")
    parser.parse_args()
    try:
        print(configuration_hash(os.environ))
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
