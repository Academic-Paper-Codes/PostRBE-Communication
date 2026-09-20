from __future__ import annotations

import unittest

import numpy as np

from postrbe import DecryptionError, PostRBE, RBEParams, SystemManager
from postrbe.serialization import (
    deserialize_ciphertext,
    deserialize_opening_proof,
    deserialize_secret_key,
    deserialize_user_params,
    serialize_ciphertext,
    serialize_opening_proof,
    serialize_secret_key,
    serialize_user_params,
    serialized_size,
)


def small_params(N: int = 4) -> RBEParams:
    # For N=4, B=2 and PostRBE requires t > (B-1)m+n = 5.
    return RBEParams(N=N, n=2, m=3, r=2, t=6, q=2_147_483_647, q_bits=64, sigma_inf=1, keep_bits=8, message_bits=256, seed=77)


class SerializationTests(unittest.TestCase):
    def test_all_external_objects_round_trip(self) -> None:
        scheme = PostRBE(small_params(), instance_id="serialization")
        scheme.setup()
        sk, user = scheme.keygen(1)
        scheme.register(1, user)
        proof = scheme.update(1)
        ciphertext = scheme.encrypt(1, b"S" * 32)

        sk2 = deserialize_secret_key(serialize_secret_key(sk))
        user2 = deserialize_user_params(serialize_user_params(user))
        proof2 = deserialize_opening_proof(serialize_opening_proof(proof))
        ciphertext2 = deserialize_ciphertext(serialize_ciphertext(ciphertext))
        np.testing.assert_array_equal(sk2.X, sk.X)
        np.testing.assert_array_equal(user2.pk, user.pk)
        np.testing.assert_array_equal(proof2.opening, proof.opening)
        self.assertEqual(scheme.decrypt(sk2, proof2, ciphertext2), b"S" * 32)
        for value in (sk, user, proof, ciphertext):
            self.assertGreater(serialized_size(value), 0)


class ScalingTests(unittest.TestCase):
    def test_capacity_overflow_creates_independent_instance(self) -> None:
        # N=4 is retained so the PostRBE dimension condition stays explicit.
        manager = SystemManager("PostRBE", small_params(N=4))
        users = [manager.register_global(i) for i in range(1, 6)]
        self.assertEqual(len(manager.instances), 2)
        self.assertNotEqual(manager.instances[0].instance_id, manager.instances[1].instance_id)
        first_scheme = manager.instances[0]
        second_scheme = manager.instances[1]
        message = b"M" * 32
        first_proof = first_scheme.update(users[0].local_identity)
        first_ct = first_scheme.encrypt(users[0].local_identity, message)
        self.assertEqual(first_scheme.decrypt(users[0].secret_key, first_proof, first_ct), message)
        second_proof = second_scheme.update(users[4].local_identity)
        second_ct = second_scheme.encrypt(users[4].local_identity, message)
        self.assertEqual(second_scheme.decrypt(users[4].secret_key, second_proof, second_ct), message)
        with self.assertRaises(DecryptionError):
            first_scheme.decrypt(users[0].secret_key, first_proof, second_ct)


if __name__ == "__main__":
    unittest.main()
