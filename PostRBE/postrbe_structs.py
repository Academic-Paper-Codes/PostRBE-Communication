# postrbe_structs.py
from dataclasses import dataclass
from typing import List
import numpy as np


@dataclass
class CRS:
    """
    Common Reference String
    """
    N_max: int
    B: int
    q: int
    n: int
    m: int
    t: int
    A_list: List[np.ndarray]               # 长度 B，每个 (n x m)
    U_list: List[np.ndarray]               # 长度 B，每个 (n x t)
    T_mat: List[List[np.ndarray]]          # B x B，每个 (m x t)
    hash_name: str
    se_mode: str


@dataclass
class PublicParams:
    """
    Public Parameters (pp)
    """
    C_list: List[np.ndarray]               # 长度 B，每个 (n x t)


@dataclass
class AuxParams:
    """
    Auxiliary Parameters (aux)
    """
    L_mat: List[List[np.ndarray]]          # B x B，每个 (m x t)
