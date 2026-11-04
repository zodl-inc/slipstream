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

Strict CI preflight validates formats and network separation before hashing.
The native core independently enforces the same build-time requirements.
"""
import argparse
from collections.abc import Mapping
import hashlib
import os
import re
import sys
import unicodedata

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
    for name in OHTTP_NAMES:
        value = environ[name]
        if "SIGNING_PUBKEY" in name:
            valid = re.fullmatch(r"[0-9a-fA-F]{64}", value) is not None
            rule = "must be a raw Ed25519 public key as 64 hex digits"
        elif "RELAY_URL" in name:
            after_scheme = value.removeprefix("https://")
            authority = re.split(r"[/?#]", after_scheme, maxsplit=1)[0]
            if authority.startswith("["):
                close = authority.find("]")
                host = authority[:close + 1] if close >= 0 else authority
            else:
                host = authority.split(":", 1)[0]
            valid = (value.startswith("https://") and host not in ("", "[]")
                     and "@" not in authority
                     and not any(char.isspace() or unicodedata.category(char) == "Cc" for char in value))
            rule = "must be a valid HTTPS relay URL with a host, no userinfo, whitespace or controls"
        else:
            valid = len(value) <= 253 and all(
                re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                for label in value.split("."))
            rule = "must be a bare DNS host name (no scheme, port, path or trailing dot)"
        if not valid:
            raise ValueError(name + " " + rule)
    ascii_lower = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
    for first, second in zip(OHTTP_NAMES[::2], OHTTP_NAMES[1::2]):
        if environ[first].translate(ascii_lower) == environ[second].translate(ascii_lower):
            raise ValueError(first + " and " + second + " must differ ignoring ASCII case")


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
