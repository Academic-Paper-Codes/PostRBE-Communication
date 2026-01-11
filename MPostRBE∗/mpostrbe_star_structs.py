# mpostrbe_star_structs.py
from dataclasses import dataclass
from typing import List
import numpy as np

@dataclass
class MCRSStar:
    N_max: int
    B: int
    q: int
    n: int
    m: int
    t: int
    # PostRBE* dimension system (paper-aligned):
    #   A   ∈ Z_q^{t×m}
    #   T_i ∈ Z_q^{m×n}
    #   U_i ∈ Z_q^{t×n}  where  A·T_i = U_i
    A: np.ndarray
    T_list: List[np.ndarray]
    U_list: List[np.ndarray]
    hash_name: str = "sha256"
    se_mode: str = "AEAD"

@dataclass
class MPublicParamsStar:
    # C_row ∈ Z_q^{t×n}
    C_list: List[np.ndarray]

@dataclass
class MAuxParamsStar:
    # L[row][col] ∈ Z_q^{t×m}
    L_mat: List[List[np.ndarray]]
