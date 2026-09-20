from __future__ import annotations

import unittest

import numpy as np

from postrbe.arithmetic import matmul_mod
from postrbe.extraction import prepare_reconciliation, reconcile


class ArithmeticTests(unittest.TestCase):
    def test_bigint_backend_matches_scalar_reference_near_modulus(self) -> None:
        q = 2_147_483_647
        a = np.asarray([[q - 1, q - 2, q - 3], [q - 4, q - 5, q - 6]], dtype=np.int64)
        b = np.asarray([[q - 7, 11], [q - 13, 17], [q - 19, 23]], dtype=np.int64)
        got = matmul_mod(a, b, q)
        expected = np.empty((2, 2), dtype=np.int64)
        for i in range(2):
            for j in range(2):
                expected[i, j] = sum(int(a[i, k]) * int(b[k, j]) for k in range(3)) % q
        np.testing.assert_array_equal(got, expected)

    def test_reconciliation_is_stable_below_stated_threshold(self) -> None:
        q = 2_147_483_647
        d = 8
        rng = np.random.default_rng(9)
        value = rng.integers(0, q, size=(2, 10), dtype=np.int64)
        prepared = prepare_reconciliation(value, q, d)
        error_bound = int(q / (2 ** (d + 1))) - 1
        errors = rng.integers(-error_bound, error_bound + 1, size=value.shape, dtype=np.int64)
        noisy = np.asarray((value.astype(object) + errors.astype(object)) % q, dtype=np.int64)
        self.assertEqual(prepared.extracted, reconcile(noisy, prepared.hint, q, d))


if __name__ == "__main__":
    unittest.main()
