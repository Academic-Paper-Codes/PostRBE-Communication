"""Independent-instance manager for populations larger than one configured N."""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Type

from .params import RBEParams
from .schemes import PostRBE, PostRBEStar, _BaseScheme
from .types import SecretKey, UserParams


SCHEME_CLASSES: dict[str, Type[_BaseScheme]] = {
    "PostRBE": PostRBE,
    "PostRBE*": PostRBEStar,
    "PostRBEStar": PostRBEStar,
}


@dataclass(frozen=True)
class ManagedUser:
    global_identity: int
    instance_index: int
    local_identity: int
    secret_key: SecretKey
    user_params: UserParams


class SystemManager:
    """Create a fresh, independent scheme instance whenever capacity is crossed."""

    def __init__(self, scheme: str, params: RBEParams):
        if scheme not in SCHEME_CLASSES:
            raise ValueError(f"unknown scheme: {scheme}")
        self.scheme_name = "PostRBE*" if scheme == "PostRBEStar" else scheme
        self.params = params
        self.instances: list[_BaseScheme] = []

    def create_instance(self) -> _BaseScheme:
        index = len(self.instances)
        instance_params = replace(self.params, seed=self.params.seed + index)
        cls = SCHEME_CLASSES[self.scheme_name]
        scheme = cls(instance_params, instance_id=f"{self.scheme_name.replace('*', 'star').lower()}-instance-{index}")
        scheme.setup()
        self.instances.append(scheme)
        return scheme

    def locate_identity(self, global_identity: int) -> tuple[int, int]:
        if isinstance(global_identity, bool) or not isinstance(global_identity, int) or global_identity <= 0:
            raise ValueError("global identity must be a positive integer")
        zero_based = global_identity - 1
        return zero_based // self.params.N, zero_based % self.params.N + 1

    def instance_for(self, global_identity: int, *, create: bool = False) -> tuple[_BaseScheme, int, int]:
        index, local_identity = self.locate_identity(global_identity)
        if create:
            while len(self.instances) <= index:
                self.create_instance()
        if index >= len(self.instances):
            raise LookupError("the required independent instance does not exist")
        return self.instances[index], index, local_identity

    def register_global(self, global_identity: int) -> ManagedUser:
        scheme, index, local_identity = self.instance_for(global_identity, create=True)
        sk, user = scheme.keygen(local_identity)
        scheme.register(local_identity, user)
        return ManagedUser(global_identity, index, local_identity, sk, user)
