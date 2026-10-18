"""Keep important regression scenarios in the published vector inventory."""

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def groups(name):
    return json.loads((ROOT / "vectors" / f"{name}.json").read_text(
        encoding="utf-8"))["testGroups"]


def cases(name):
    return [t for g in groups(name) for t in g["tests"]]


class TestVectorCoverage(unittest.TestCase):
    def test_sm3_padding_boundaries_and_binary_input(self):
        messages = [bytes.fromhex(t["msg"]) for t in cases("sm3")]
        self.assertTrue({0, 54, 55, 56, 57, 119, 120, 121, 4096}
                        <= {len(m) for m in messages})
        self.assertIn(b"\x00abc\x00\x80\xff\x00", messages)
        self.assertIn("国密算法测试".encode(), messages)

    def test_hmac_normalization_boundary_and_empty_message(self):
        pairs = {(len(bytes.fromhex(t["key"])), len(bytes.fromhex(t["msg"])))
                 for t in cases("hmac-sm3")}
        self.assertTrue({(63, 0), (64, 0), (65, 0), (131, 1024)} <= pairs)

    def test_sm4_counter_carry_and_both_directions(self):
        for direction in ("encrypt", "decrypt"):
            tests = [t for g in groups("sm4") if g["mode"] == "CTR"
                     and g["direction"] == direction for t in g["tests"]]
            self.assertTrue({47, 48, 49, 1024} <= {len(t["pt"]) // 2 for t in tests})
            self.assertTrue({"000000000000000000000000000000ff",
                             "0000000000000000000000000000ffff"}
                            <= {t["iv"] for t in tests if len(t["pt"]) > 32})

    def test_authenticated_block_boundaries(self):
        lengths = {len(t["pt"]) // 2 for t in cases("sm4-ctr-hmac-sm3")}
        self.assertTrue({0, 1, 15, 16, 17, 31, 32, 33, 47, 48, 49, 256} <= lengths)

    def test_sm2_valid_signatures_for_both_identities(self):
        for group in groups("sm2"):
            self.assertTrue(any(t["expected"] for t in group["tests"]))
            self.assertTrue(any(not t["expected"] for t in group["tests"]))

    def test_sm2_all_ciphertext_encodings_and_rejection_cases(self):
        tests = cases("sm2-encryption")
        decrypt = {(t["ciphertextFormat"], len(t["msg"]) // 2) for t in tests
                   if t["operation"] == "decrypt" and t["expected"]}
        self.assertTrue({(fmt, size) for fmt in ("der", "c1c2c3", "c1c3c2")
                         for size in (1, 31, 32, 33, 128)} <= decrypt)
        rejects = {t.get("description") for t in tests
                   if t["operation"] == "decrypt" and not t["expected"]}
        self.assertTrue({"changed C2", "changed C3", "wrong private key"} <= rejects)


if __name__ == "__main__":
    unittest.main()
