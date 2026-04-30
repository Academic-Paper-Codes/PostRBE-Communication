"""Parameter definitions for PostRBE prototype benchmarks."""
from __future__ import annotations

from dataclasses import dataclass
from math import ceil, sqrt
from typing import Optional


@dataclass(frozen=True)
class RBEParams:
    """Unified benchmark parameters.

    q_bits is the paper/measurement modulus size. q is only the runtime modulus
    used by this Python prototype to keep NumPy arithmetic manageable. Size and
    ciphertext estimates always use q_bits, not q.
    """

    N: int = 100
    n: int = 16
    m: int = 32
    r: int = 16
    t: Optional[int] = None
    q: int = 2_147_483_647  # runtime modulus for the prototype, not the paper q
    q_bits: int = 64
    sigma_inf: int = 2
    keep_bits: int = 10  # d: number of high bits extracted by F[·]
    message_bits: int = 256
    seed: int = 12345

    @property
    def B(self) -> int:
        return int(ceil(sqrt(self.N)))

    @property
    def element_bytes(self) -> int:
        return int(ceil(self.q_bits / 8))

    @property
    def message_bytes(self) -> int:
        return int(ceil(self.message_bits / 8))

    @property
    def short_min(self) -> int:
        return -int(self.sigma_inf)

    @property
    def short_max(self) -> int:
        return int(self.sigma_inf)

    def with_t_for_scheme(self, scheme: str) -> "RBEParams":
        """Fill t using the unified experiment rule for each scheme.

        PostRBE:    t > (B-1)m + n, so use (B-1)m+n+1.
        PostRBE*:   t > max(r,n). For the paper experiment, use fixed t=512
                    when it satisfies the condition; otherwise use max(r,n)+1.
        """
        if self.t is not None:
            return self
        s = scheme.lower().replace("*", "star")
        if s in {"postrbe", "base"}:
            t = (self.B - 1) * self.m + self.n + 1
        elif s in {"postrbestar", "star", "postrbe_star"}:
            t = max(512, max(self.r, self.n) + 1)
        else:
            raise ValueError(f"unknown scheme: {scheme}")
        return RBEParams(
            N=self.N,
            n=self.n,
            m=self.m,
            r=self.r,
            t=t,
            q=self.q,
            q_bits=self.q_bits,
            sigma_inf=self.sigma_inf,
            keep_bits=self.keep_bits,
            message_bits=self.message_bits,
            seed=self.seed,
        )

    def validate(self) -> None:
        if self.m < self.n:
            raise ValueError("Require m >= n for the prototype A=[I|0] setup")
        if self.t is None:
            raise ValueError("t must be set; call with_t_for_scheme first")
        if self.t <= 0 or self.r <= 0 or self.n <= 0 or self.m <= 0:
            raise ValueError("dimensions must be positive")
        if self.q <= 2:
            raise ValueError("runtime q must be > 2")
        if self.q_bits <= 0:
            raise ValueError("q_bits must be positive")
        if self.sigma_inf < 0:
            raise ValueError("sigma_inf must be nonnegative")
        if not (1 <= self.keep_bits <= self.q_bits):
            raise ValueError("keep_bits must be in [1, q_bits]")
