"""Reproduce the October 2026 regression-vector extension (test keys only)."""

from __future__ import annotations

import argparse
import copy
from contextlib import redirect_stdout
import io
from importlib.metadata import version as package_version
import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from gmssl import sm2  # noqa: E402
import authenticated_sm4  # noqa: E402
import gmssl_backend  # noqa: E402
import hmac_sm3_runner  # noqa: E402
import runner  # noqa: E402
import sm2_cipher  # noqa: E402
import sm2_runner  # noqa: E402
import sm4_runner  # noqa: E402

VECTOR_NAMES = ("sm3", "hmac-sm3", "sm4", "sm4-ctr-hmac-sm3", "sm2", "sm2-encryption")
BATCH = "boundary-2026-10"


def sequence(length: int) -> bytes:
    return bytes(i % 256 for i in range(length))


def reference_encoding(raw: bytes, fmt: str) -> bytes:
    """Encode generated C1C3C2 independently of the converter under test."""
    c1, c3, c2 = raw[:65], raw[65:97], raw[97:]
    if fmt == "c1c3c2":
        return raw
    if fmt == "c1c2c3":
        return c1 + c2 + c3

    def tlv(tag, data):
        n = len(data)
        length = bytes([n]) if n < 128 else (
            bytes([0x80 + (n.bit_length() + 7) // 8])
            + n.to_bytes((n.bit_length() + 7) // 8, "big"))
        return bytes([tag]) + length + data

    def integer(data):
        data = data.lstrip(b"\x00") or b"\x00"
        return tlv(2, b"\x00" + data if data[0] & 0x80 else data)

    if fmt != "der":
        raise ValueError(fmt)
    return tlv(0x30, integer(c1[1:33]) + integer(c1[33:65])
               + tlv(4, c3) + tlv(4, c2))


def generate(openssl: str) -> dict:
    version = subprocess.check_output([openssl, "version"], text=True).strip()
    source = f"Generated/cross-checked with {version} and Python gmssl {package_version('gmssl')}"
    docs = {name: json.loads((ROOT / "vectors" / f"{name}.json").read_text(
        encoding="utf-8")) for name in VECTOR_NAMES}
    # Replace only this generator's batch, preserving hand-maintained vectors.
    for doc in docs.values():
        for group in doc["testGroups"]:
            group["tests"] = [t for t in group["tests"] if t.get("batch") != BATCH]
        doc["testGroups"] = [g for g in doc["testGroups"] if g["tests"]]
    next_ids = {name: max(t["tcId"] for g in doc["testGroups"] for t in g["tests"]) + 1
                for name, doc in docs.items()}

    def add(name, group, description, **fields):
        item = {"tcId": next_ids[name], "description": description,
                "sourceType": "regression", "source": source, "batch": BATCH, **fields}
        next_ids[name] += 1
        group["tests"].append(item)
        return item

    messages = [(f"{n}-byte incremental message", sequence(n))
                for n in (54, 57, 119, 120, 121, 255, 256, 257, 1024, 4096)]
    messages += [("one ff byte", b"\xff"), ("64 ff bytes", b"\xff" * 64),
                 ("UTF-8 Chinese text", "国密算法测试".encode()),
                 ("embedded NUL and high-bit bytes", b"\x00abc\x00\x80\xff\x00"),
                 ("16-byte incremental message", sequence(16)),
                 ("65-byte incremental message", sequence(65))]
    for label, msg in messages:
        md = runner.sm3_digest(openssl, msg)
        assert md == gmssl_backend.gmssl_sm3(msg), label
        add("sm3", docs["sm3"]["testGroups"][0], label,
            msg=msg.hex(), msgLen=len(msg) * 8, md=md)

    hmac_inputs = [(sequence(n), msg) for n in (63, 64, 65)
                   for msg in (b"", sequence(119))]
    hmac_inputs += [(sequence(131), sequence(n)) for n in (55, 56, 64, 65, 1024)]
    hmac_inputs += [(b"\xff", "消息认证".encode())]
    for key, msg in hmac_inputs:
        tag = hmac_sm3_runner.hmac_sm3(openssl, key.hex(), msg)
        assert tag == gmssl_backend.gmssl_hmac_sm3(key, msg)
        add("hmac-sm3", docs["hmac-sm3"]["testGroups"][0],
            f"{len(key)}-byte key and {len(msg)}-byte message",
            key=key.hex(), msg=msg.hex(), msgLen=len(msg) * 8, tag=tag)

    key, iv = sequence(16), sequence(16)
    specs = [("CTR", key, iv, sequence(n), f"{n}-byte boundary") for n in (47, 48, 49)]
    specs += [("CTR", key, bytes.fromhex(value), sequence(49), label) for value, label in
              (("000000000000000000000000000000ff", "low-byte counter carry"),
               ("0000000000000000000000000000ffff", "multi-byte counter carry"))]
    specs += [(mode, bytes([value]) * 16, None if mode == "ECB" else iv,
               bytes([value]) * length, f"all-{value:02x} key/data")
              for mode in ("ECB", "CBC") for value, length in ((0, 16), (255, 64))]
    specs += [("CBC", key, b"\xa5" * 16, sequence(32), "alternate IV"),
              ("CTR", key, iv, sequence(1024), "1024-byte message")]
    specs += [(mode, key, None if mode == "ECB" else iv, sequence(256),
               "256-byte message") for mode in ("ECB", "CBC")]
    for mode, key, iv, msg, label in specs:
        ct = sm4_runner.sm4_crypt(openssl, mode, "encrypt", key.hex(),
                                  iv.hex() if iv else None, msg)
        assert ct == gmssl_backend.gmssl_sm4_crypt(mode, "encrypt", key, iv, msg)
        for direction in ("encrypt", "decrypt"):
            group = next(g for g in docs["sm4"]["testGroups"]
                         if g["mode"] == mode and g["direction"] == direction)
            fields = dict(key=key.hex(), pt=msg.hex(), ct=ct.hex())
            if iv is not None:
                fields["iv"] = iv.hex()
            add("sm4", group, f"{mode} {direction}: {label}", **fields)

    for index, msg in enumerate([sequence(n) for n in (15, 31, 32, 47, 48, 49, 256)]
                                + ["认证加密实验".encode()]):
        key, mac_key, iv = sequence(16), sequence(32), (index + 1).to_bytes(16, "big")
        package = authenticated_sm4.encrypt_and_authenticate(
            openssl, key.hex(), mac_key.hex(), msg, iv=iv)
        ct = gmssl_backend.gmssl_sm4_crypt("CTR", "encrypt", key, iv, msg)
        # Independently assemble the documented authenticated bytes.
        auth = b"GMENC\x01SM4-CTR-HMAC-SM3" + iv + len(ct).to_bytes(8, "big") + ct
        assert ct.hex() == package["ciphertext"]
        assert gmssl_backend.gmssl_hmac_sm3(mac_key, auth) == package["tag"]
        add("sm4-ctr-hmac-sm3", docs["sm4-ctr-hmac-sm3"]["testGroups"][0],
            f"Authenticated {len(msg)}-byte message with nonzero keys",
            sm4Key=key.hex(), hmacKey=mac_key.hex(), iv=iv.hex(), pt=msg.hex(),
            ct=ct.hex(), tag=package["tag"])

    # Fixed d and k are strictly for reproducible public regression fixtures.
    private = (1).to_bytes(32, "big")
    public = bytes.fromhex(docs["sm2"]["testGroups"][0]["tests"][0]["publicKey"])
    default_group = docs["sm2"]["testGroups"][0]
    signing_inputs = [sequence(n) for n in (1, 31, 32, 33, 65, 128)] + ["国密签名".encode()]
    for index, msg in enumerate(signing_inputs + [b"alternate identity"]):
        group = default_group if index < 7 else docs["sm2"]["testGroups"][1]
        uid = bytes.fromhex(group["userId"])
        curve = sm2.default_ecc_table
        za = bytes.fromhex(gmssl_backend.gmssl_sm3(
            (len(uid) * 8).to_bytes(2, "big") + uid + bytes.fromhex(
                curve["a"] + curve["b"] + curve["g"]) + public[1:]))
        digest = bytes.fromhex(gmssl_backend.gmssl_sm3(za + msg))
        signer = sm2.CryptSM2(private_key=private.hex(), public_key=public.hex()[2:])
        raw = signer.sign(digest, f"{index + 10:064x}")
        sig = sm2_runner.raw_signature_to_der(bytes.fromhex(raw))
        assert sm2_runner.openssl_sm2_verify(openssl, public, uid, msg, sig)
        add("sm2", group, f"Valid {len(msg)}-byte message signature",
            operation="verify", msg=msg.hex(), msgLen=len(msg)*8,
            publicKey=public.hex(), signature=sig.hex(), expected=True,
            source=source + f"; test-only d=1, k={index + 10}")
    baseline_signature = copy.deepcopy(default_group["tests"][-1])
    for field in ("msg", "signature"):
        item = copy.deepcopy(baseline_signature)
        data = bytearray.fromhex(item[field])
        data[-1] ^= 1
        item[field] = data.hex()
        for name in ("tcId", "description", "expected", "sourceType", "source", "batch"):
            item.pop(name)
        add("sm2", default_group, f"Modified {field} after signing",
            **item, expected=False, sourceType="negative")

    group = docs["sm2-encryption"]["testGroups"][0]
    raw_cipher = None
    for index, length in enumerate((1, 31, 32, 33, 128)):
        msg = sequence(length)
        with patch("gmssl.func.random_hex", return_value=f"{index + 30:064x}"):
            raw_cipher = sm2_cipher.gmssl_encrypt("", public, msg)
        for fmt in ("c1c3c2", "c1c2c3", "der"):
            ct = reference_encoding(raw_cipher, fmt)
            add("sm2-encryption", group, f"Decrypt {length}-byte message in {fmt}",
                operation="decrypt", privateKey=private.hex(), msg=msg.hex(),
                ciphertext=ct.hex(), ciphertextFormat=fmt, expected=True,
                source=source + f"; test-only d=1, k={index + 30}")
    for label, offset, d in (("changed C2", 97, 1), ("changed C3", 65, 1),
                              ("wrong private key", None, 2)):
        ct = bytearray(raw_cipher)
        if offset is not None:
            ct[offset] ^= 1
        add("sm2-encryption", group, label, operation="decrypt",
            privateKey=f"{d:064x}", msg=sequence(128).hex(), ciphertext=ct.hex(),
            ciphertextFormat="c1c3c2", expected=False, sourceType="negative")
    for from_fmt in ("c1c3c2", "c1c2c3", "der"):
        for to_fmt in ("c1c3c2", "c1c2c3", "der"):
            if from_fmt == to_fmt:
                continue
            add("sm2-encryption", group, f"128-byte message: {from_fmt} to {to_fmt}",
                operation="convert", sourceFormat=from_fmt, targetFormat=to_fmt,
                ciphertext=reference_encoding(raw_cipher, from_fmt).hex(),
                expectedCiphertext=reference_encoding(raw_cipher, to_fmt).hex())

    # Verify everything, including negative cases, before writing any files.
    for name, doc in docs.items():
        results = []
        with redirect_stdout(io.StringIO()):
            code = runner.run_document(doc, openssl, backend="cross", results=results)
        if code:
            raise RuntimeError(f"{name}: cross-validation failed: {results}")
        print(f"{name}: {len(results)} passed")
    return docs


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--openssl", default="openssl", help="OpenSSL 3 executable")
    args = parser.parse_args()
    documents = generate(runner.resolve_openssl(args.openssl))
    for name, doc in documents.items():
        (ROOT / "vectors" / f"{name}.json").write_text(
            json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
