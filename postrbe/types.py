"""Typed external objects for the PostRBE functional implementation."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import numpy as np

Array = np.ndarray


class PostRBEError(Exception):
    """Base class for expected artifact errors."""


class SetupRequiredError(PostRBEError):
    pass


class RegistrationError(PostRBEError):
    pass


class VerificationError(PostRBEError):
    pass


class DecryptionError(PostRBEError):
    pass


class SerializationError(PostRBEError):
    pass


@dataclass(frozen=True)
class SecretKey:
    scheme: str
    instance_id: str
    identity: int
    block: int
    position: int
    X: Array

    @property
    def id(self) -> int:
        return self.identity

    @property
    def pos(self) -> int:
        return self.position


@dataclass(frozen=True)
class UserParams:
    scheme: str
    instance_id: str
    identity: int
    pk: Array
    up: Any | None


@dataclass(frozen=True)
class OpeningProof:
    scheme: str
    instance_id: str
    identity: int
    block: int
    position: int
    state_version: int
    opening: Array


@dataclass(frozen=True)
class Ciphertext:
    scheme: str
    instance_id: str
    identity: int
    block: int
    position: int
    state_version: int
    c1: Array
    c2: Array
    reconciliation_hint: Array
    nonce: bytes
    c3: bytes
    _audit_shared: Array | None = field(default=None, repr=False, compare=False)


@dataclass(frozen=True)
class RegistrationRecord:
    scheme: str
    instance_id: str
    identity: int
    block: int
    position: int
    pk: Array
    up: Any
    registered_version: int


@dataclass(frozen=True)
class StateReceipt:
    action: str
    scheme: str
    instance_id: str
    identity: int
    old_version: int
    new_version: int


@dataclass(frozen=True)
class CorrectnessAudit:
    noise_infinity_norm: int
    allowed_threshold: float
    within_bound: bool
    reconciliation_matches: bool
