# postrbe_star_structs.py
from dataclasses import dataclass
from typing import List
import numpy as np

@dataclass
class CRSStar:
    N_max: int
    B: int
    q: int
    n: int
    m: int
    t: int
    # PostRBE* (paper, Fig.4) dimensions:
    #   A   ∈ Z_q^{t×m}
    #   T_i ∈ Z_q^{m×n}
    #   U_i ∈ Z_q^{t×n}  where  A·T_i = U_i
    A: np.ndarray                   # (t x m)
    T_list: List[np.ndarray]        # B items of shape (m x n)
    U_list: List[np.ndarray]        # B items of shape (t x n)
    hash_name: str = "sha256"
    se_mode: str = "AEAD"

@dataclass
class PublicParamsStar:
    C_list: List[np.ndarray]        # B items of shape (t x n)

@dataclass
class AuxParamsStar:
    L_mat: List[List[np.ndarray]]   # B x B items of shape (t x m)
