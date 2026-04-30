from dataclasses import dataclass
import math
from typing import List


TARGET_N = [10**3, 10**4, 10**5, 10**6, 10**7]


def ceil_sqrt(n: int) -> int:
    return int(math.ceil(math.sqrt(n)))


def ceil_log2(n: int) -> int:
    return int(math.ceil(math.log2(n)))


@dataclass(frozen=True)
class UnifiedParams:
    """Parameters shared with the PostRBE experiment table.

    Notes:
    - B follows the user's PostRBE table: B = ceil(sqrt(N)).
    - The DKLLMR/Eurocrypt'23 RBE transformation itself mainly uses ell = ceil(log2(N)).
    - r and t are kept for CSV compatibility. They are not algorithmic dimensions of this baseline.
    """
    N: int
    n: int = 256
    m: int = 512
    r: int = 128
    d: int = 10
    q_bits: int = 64
    sigma_inf: int = 2
    short_min: int = -2
    short_max: int = 2
    message_bits: int = 256
    # Scheme-specific / unmatched parameter: ring degree for elements of R_q.
    # If you want the exact same Z_q scalar model as PostRBE, set ring_degree=1.
    # If you want a cyclotomic ring cost model, set e.g. ring_degree=128.
    ring_degree: int = 128
    poly_mul_model: str = "ntt"  # scalar, naive, ntt
    commit_entries: int = 0       # 0 means default n entries for SIS-style commitment

    @property
    def B(self) -> int:
        return ceil_sqrt(self.N)

    @property
    def ell(self) -> int:
        return ceil_log2(self.N)

    @property
    def t_for_csv(self) -> str:
        return "NA"

    @property
    def r_for_csv(self) -> int:
        # kept for compatibility with the unified parameter table; this RBE baseline does not use r.
        return self.r

    @property
    def short_range(self) -> str:
        return f"[{self.short_min},{self.short_max}]"


def parse_int_list(items: List[str]) -> List[int]:
    out = []
    for item in items:
        for piece in str(item).replace(',', ' ').split():
            if piece:
                out.append(int(piece))
    return out
