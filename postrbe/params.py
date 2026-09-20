"""Parameter definitions and validation for the PostRBE artifact."""
from __future__ import annotations

from dataclasses import dataclass, replace
from math import ceil, sqrt
from typing import Optional


@dataclass(frozen=True)
class RBEParams:
    """Parameters shared by the functional and accounting profiles.

    ``q`` is the executable prototype modulus. ``q_bits`` is the paper/accounting
    modulus width and is deliberately kept separate so that paper-scale size
    accounting never depends on the small functional-demo modulus.
    """

    N: int = 100
    n: int = 16
    m: int = 32
    r: int = 16
    t: Optional[int] = None
    q: int = 2_147_483_647
    q_bits: int = 64
    sigma_inf: int = 2
    keep_bits: int = 10
    message_bits: int = 256
    seed: int = 12345
    arithmetic_backend: str = "python_bigint"

    @property
    def B(self) -> int:
        return int(ceil(sqrt(self.N)))

    @property
    def block_count(self) -> int:
        return int(ceil(self.N / self.B))

    @property
    def element_bytes(self) -> int:
        return int(ceil(self.q_bits / 8))

    @property
    def runtime_element_bytes(self) -> int:
        return int(ceil(self.q.bit_length() / 8))

    @property
    def message_bytes(self) -> int:
        return int(ceil(self.message_bits / 8))

    @property
    def short_min(self) -> int:
        return -int(self.sigma_inf)

    @property
    def short_max(self) -> int:
        return int(self.sigma_inf)

    @property
    def extraction_threshold(self) -> float:
        return self.q / (2 ** (self.keep_bits + 1))

    def with_t_for_scheme(self, scheme: str) -> "RBEParams":
        if self.t is not None:
            return self
        normalized = scheme.lower().replace("*", "star").replace("_", "")
        if normalized in {"postrbe", "base"}:
            t = (self.B - 1) * self.m + self.n + 1
        elif normalized in {"postrbestar", "star"}:
            t = max(512, max(self.r, self.n) + 1)
        else:
            raise ValueError(f"unknown scheme: {scheme}")
        return replace(self, t=t)

    def validate(self, scheme: str | None = None) -> None:
        if self.N <= 0:
            raise ValueError("N must be positive")
        if self.n <= 0 or self.m <= 0 or self.r <= 0:
            raise ValueError("n, m, and r must be positive")
        if self.m < self.n:
            raise ValueError("m must be >= n for the functional A=[I|0] backend")
        if self.t is None or self.t <= 0:
            raise ValueError("t must be set; call with_t_for_scheme first")
        if self.q <= 2 or self.q > (2**63 - 1):
            raise ValueError("runtime q must be in [3, 2^63-1]")
        if self.q_bits <= 0:
            raise ValueError("q_bits must be positive")
        if self.sigma_inf <= 0:
            raise ValueError("sigma_inf must be positive for noisy functional tests")
        if not (1 <= self.keep_bits < self.q.bit_length()):
            raise ValueError("keep_bits must be smaller than runtime q bit length")
        if self.message_bits <= 0 or self.message_bits % 8 != 0:
            raise ValueError("message_bits must be a positive multiple of 8")
        if self.arithmetic_backend != "python_bigint":
            raise ValueError("functional correctness requires arithmetic_backend='python_bigint'")
        if scheme:
            normalized = scheme.lower().replace("*", "star").replace("_", "")
            if normalized in {"postrbe", "base"}:
                lower_bound = (self.B - 1) * self.m + self.n
                if self.t <= lower_bound:
                    raise ValueError(f"PostRBE requires t > {lower_bound}")
            elif normalized in {"postrbestar", "star"}:
                if self.t <= max(self.r, self.n):
                    raise ValueError("PostRBE* requires t > max(r,n)")
            else:
                raise ValueError(f"unknown scheme: {scheme}")

    def validate_identity(self, identity: int) -> None:
        if isinstance(identity, bool) or not isinstance(identity, int):
            raise TypeError("identity must be an integer")
        if not 1 <= identity <= self.N:
            raise ValueError(f"identity must be in [1, {self.N}], got {identity}")
