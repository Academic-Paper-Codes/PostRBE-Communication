from __future__ import annotations

import unittest
from dataclasses import replace

import numpy as np

from postrbe import DecryptionError, PostRBE, PostRBEStar, RBEParams, RegistrationError
from postrbe.schemes import id_to_block_pos
from postrbe.types import UserParams


def params_for(cls):
    t = 6 if cls is PostRBE else 4
    return RBEParams(
        N=4,
        n=2,
        m=3,
        r=2,
        t=t,
        q=2_147_483_647,
        q_bits=64,
        sigma_inf=1,
        keep_bits=8,
        message_bits=256,
        seed=2027,
    )


class ParameterAndSetupTests(unittest.TestCase):
    def test_index_boundaries(self) -> None:
        self.assertEqual(id_to_block_pos(1, 3, 8), (0, 0))
        self.assertEqual(id_to_block_pos(3, 3, 8), (0, 2))
        self.assertEqual(id_to_block_pos(4, 3, 8), (1, 0))
        self.assertEqual(id_to_block_pos(8, 3, 8), (2, 1))
        for invalid in (0, -1, 9):
            with self.assertRaises(ValueError):
                id_to_block_pos(invalid, 3, 8)

    def test_setup_relations_and_no_trapdoor_export(self) -> None:
        for cls in (PostRBE, PostRBEStar):
            with self.subTest(cls=cls.__name__):
                scheme = cls(params_for(cls), instance_id="setup-test")
                audit = scheme.setup()
                self.assertTrue(scheme.setup_self_check())
                self.assertFalse(audit["trapdoor_exported"])
                public = scheme.public_state()
                self.assertNotIn("trapdoor", public)
                self.assertEqual(len(scheme.C), scheme.params.block_count)
                self.assertTrue(all(not np.any(value) for value in scheme.C.values()))
                self.assertTrue(all(not np.any(value) for value in scheme.L.values()))


class SchemeBehaviorMixin:
    SCHEME = PostRBE

    def make_scheme(self):
        scheme = self.SCHEME(params_for(self.SCHEME), instance_id=f"test-{self.SCHEME.__name__}")
        scheme.setup()
        return scheme

    def test_full_keygen_and_atomic_registration(self) -> None:
        scheme = self.make_scheme()
        sk, pk, up = scheme.keygen_full(1)
        user = UserParams(scheme.name, scheme.instance_id, 1, pk, up)
        before = scheme.state_digest()

        bad_pk = pk.copy()
        bad_pk[0, 0] = (int(bad_pk[0, 0]) + 1) % scheme.q
        bad = replace(user, pk=bad_pk)
        with self.assertRaises(RegistrationError):
            scheme.register(1, bad)
        self.assertEqual(before, scheme.state_digest())

        receipt = scheme.register(1, user)
        self.assertEqual(receipt.new_version, 1)
        with self.assertRaises(RegistrationError):
            scheme.register(1, user)
        self.assertEqual(sk.identity, 1)

    def test_tampered_upload_is_rejected_atomically(self) -> None:
        scheme = self.make_scheme()
        _, user = scheme.keygen(1)
        before = scheme.state_digest()
        if isinstance(user.up, list):
            tampered_up = [None if x is None else x.copy() for x in user.up]
            index = next(i for i, x in enumerate(tampered_up) if x is not None)
            tampered_up[index][0, 0] = (int(tampered_up[index][0, 0]) + 1) % scheme.q
        else:
            tampered_up = user.up.copy()
            tampered_up[0, 0] = (int(tampered_up[0, 0]) + 1) % scheme.q
        with self.assertRaises(RegistrationError):
            scheme.register(1, replace(user, up=tampered_up))
        self.assertEqual(before, scheme.state_digest())

    def test_wrong_instance_identity_and_shape_are_rejected(self) -> None:
        scheme = self.make_scheme()
        _, user = scheme.keygen(1)
        before = scheme.state_digest()
        invalid_values = (
            replace(user, instance_id="another-instance"),
            replace(user, identity=2),
            replace(user, pk=user.pk[:, :-1]),
        )
        for invalid in invalid_values:
            with self.subTest(invalid=invalid.instance_id, shape=invalid.pk.shape):
                with self.assertRaises(RegistrationError):
                    scheme.register(1, invalid)
                self.assertEqual(before, scheme.state_digest())

    def test_membership_nonmembership_and_roundtrip(self) -> None:
        scheme = self.make_scheme()
        sk, user = scheme.keygen(1)
        scheme.register(1, user)
        member_proof = scheme.update(1)
        nonmember_proof = scheme.update(2)
        self.assertTrue(scheme.verify_membership(1, user.pk, member_proof))
        self.assertFalse(scheme.verify_nonmembership(1, member_proof))
        self.assertFalse(scheme.verify_membership(2, user.pk, nonmember_proof))
        self.assertTrue(scheme.verify_nonmembership(2, nonmember_proof))
        tampered_opening = member_proof.opening.copy()
        tampered_opening[0, 0] = (int(tampered_opening[0, 0]) + 1) % scheme.q
        self.assertFalse(scheme.verify_membership(1, user.pk, replace(member_proof, opening=tampered_opening)))

        message = bytes(range(32))
        ciphertext = scheme.encrypt(1, message)
        self.assertEqual(scheme.decrypt(sk, member_proof, ciphertext), message)
        audit = scheme.correctness_audit(sk, member_proof, ciphertext)
        self.assertGreater(audit.noise_infinity_norm, 0)
        self.assertTrue(audit.within_bound)
        self.assertTrue(audit.reconciliation_matches)

        tampered = replace(ciphertext, c3=ciphertext.c3[:-1] + bytes([ciphertext.c3[-1] ^ 1]))
        with self.assertRaises(DecryptionError):
            scheme.decrypt(sk, member_proof, tampered)

    def test_wrong_key_opening_and_stale_proof_fail(self) -> None:
        scheme = self.make_scheme()
        sk1, user1 = scheme.keygen(1)
        scheme.register(1, user1)
        proof1 = scheme.update(1)
        ciphertext = scheme.encrypt(1, b"A" * 32)
        sk2, user2 = scheme.keygen(2)
        with self.assertRaises(DecryptionError):
            scheme.decrypt(sk2, proof1, ciphertext)
        scheme.register(2, user2)
        self.assertFalse(scheme.verify_membership(1, user1.pk, proof1))
        with self.assertRaises(DecryptionError):
            scheme.decrypt(sk1, scheme.update(1), ciphertext)

    def test_revocation_updates_current_state_and_preserves_other_user(self) -> None:
        scheme = self.make_scheme()
        sk1, user1 = scheme.keygen(1)
        sk2, user2 = scheme.keygen(2)
        scheme.register(1, user1)
        scheme.register(2, user2)
        scheme.revoke(1)
        proof1 = scheme.update(1)
        proof2 = scheme.update(2)
        self.assertFalse(scheme.verify_membership(1, user1.pk, proof1))
        self.assertTrue(scheme.verify_nonmembership(1, proof1))
        self.assertTrue(scheme.verify_membership(2, user2.pk, proof2))
        with self.assertRaises(RegistrationError):
            scheme.revoke(1)

        # The documented policy permits a fresh explicit registration after
        # revocation, without retaining or double-counting the old record.
        _, replacement_user = scheme.keygen(1)

        message = b"B" * 32
        ct2 = scheme.encrypt(2, message)
        self.assertEqual(scheme.decrypt(sk2, proof2, ct2), message)
        ct1 = scheme.encrypt(1, message)
        with self.assertRaises(DecryptionError):
            scheme.decrypt(sk1, proof1, ct1)
        scheme.register(1, replacement_user)
        self.assertTrue(scheme.verify_membership(1, replacement_user.pk, scheme.update(1)))


class PostRBETests(SchemeBehaviorMixin, unittest.TestCase):
    SCHEME = PostRBE


class PostRBEStarTests(SchemeBehaviorMixin, unittest.TestCase):
    SCHEME = PostRBEStar


if __name__ == "__main__":
    unittest.main()
