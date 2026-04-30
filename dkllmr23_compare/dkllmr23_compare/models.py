from dataclasses import asdict
from typing import Dict, Tuple
import math
from .params import UnifiedParams


def poly_mul_cost(p: UnifiedParams) -> float:
    """Return scalar-muladd-equivalent cost for one multiplication in R_q.

    scalar: treat an R_q element as one Z_q scalar element.
    naive : polynomial multiplication cost O(D^2).
    ntt   : rough NTT-style cost O(D log2 D). Constants are intentionally not hidden,
            because this file is for relative estimates rather than a secure implementation.
    """
    D = max(1, int(p.ring_degree))
    model = p.poly_mul_model.lower()
    if model == "scalar":
        return 1.0
    if model == "naive":
        return float(D * D)
    if model == "ntt":
        if D <= 1:
            return 1.0
        return float(D * math.log2(D))
    raise ValueError(f"unknown poly_mul_model: {p.poly_mul_model}")


def ring_entry_bytes(p: UnifiedParams) -> float:
    """Bytes to store one R_q element as ring_degree coefficients in Z_q."""
    return p.ring_degree * p.q_bits / 8.0


def commit_entries(p: UnifiedParams) -> int:
    """SIS-style commitment size measured in R_q elements.

    The Eurocrypt'23 RBE transformation uses an external commitment. The paper notes SIS commitments
    as a simple instantiation. We model one commitment as one vector in R_q^n by default.
    """
    return p.n if p.commit_entries == 0 else int(p.commit_entries)


def le_ciphertext_entries(p: UnifiedParams) -> int:
    """LE ciphertext entries from Fig. 2: (c0,...,c_ell,d).

    c_j for j<ell has length 2m, c_ell has length m, d has length 1.
    Total = (2*ell+1)*m + 1 R_q elements.
    """
    return (2 * p.ell + 1) * p.m + 1


def rbe_ciphertext_entries(p: UnifiedParams) -> int:
    """Figure 3 RBE ciphertext entries.

    For each of ell states, it includes two LE ciphertexts plus one commitment.
    """
    return p.ell * (2 * le_ciphertext_entries(p) + commit_entries(p))


def le_setup_units(p: UnifiedParams) -> float:
    # Generate A0, A1, B in R_q^{n x m}; random generation cost is counted as one unit per entry.
    return float(3 * p.n * p.m + p.n)


def le_kgen_units(p: UnifiedParams) -> float:
    # y = B*x, B in R_q^{n x m}, x in R_p^m.
    return p.n * p.m * poly_mul_cost(p)


def le_update_units(p: UnifiedParams) -> float:
    # Path update over ell levels; each level computes A0*u0 + A1*u1.
    return p.ell * (2 * p.n * p.m) * poly_mul_cost(p)


def le_wgen_units(p: UnifiedParams) -> float:
    # Witness generation mainly does gadget decomposition along the path; model as O(ell*m).
    return float(p.ell * 2 * p.m)


def le_enc_units(p: UnifiedParams) -> float:
    # For each level: (r_j, r_{j+1}) * B_j with rough 4nm cost; final c_ell: nm; d: n.
    return (p.ell * (4 * p.n * p.m) + p.n * p.m + p.n) * poly_mul_cost(p)


def le_dec_units(p: UnifiedParams) -> float:
    # Inner products against witness and secret: (2*ell+1)m R_q multiplications.
    return ((2 * p.ell + 1) * p.m) * poly_mul_cost(p)


def rbe_operation_counts(p: UnifiedParams, register_model: str = "worst") -> Dict[str, float]:
    """Return operation-count/work-unit estimates for the Eurocrypt'23 LE->RBE baseline.

    register_model:
      - worst: Fig. 3 merge can take O(N) LE updates in the worst case.
      - amortized: approximate O(log N) LE updates per registration.
      - sqrt: alternative remark with O(sqrt N) update cost.
    """
    register_model = register_model.lower()
    setup = le_setup_units(p) + p.ell * p.n  # output ell state entries
    keygen = le_kgen_units(p)
    if register_model == "worst":
        register = p.N * le_update_units(p)
    elif register_model == "amortized":
        register = p.ell * le_update_units(p)
    elif register_model == "sqrt":
        register = p.B * le_update_units(p)
    else:
        raise ValueError("register_model must be worst, amortized, or sqrt")

    cmt = commit_entries(p) * poly_mul_cost(p)
    encrypt = p.ell * (2 * le_enc_units(p) + cmt)
    update = le_wgen_units(p)
    decrypt = 2 * le_dec_units(p) + cmt
    decrypt_update = update + decrypt

    return {
        "Setup": setup,
        "KeyGen": keygen,
        "Register": register,
        "Encrypt": encrypt,
        "DecryptUpdate": decrypt_update,
    }


def size_counts(p: UnifiedParams) -> Dict[str, float]:
    ct_entries = rbe_ciphertext_entries(p)
    ct_bytes = ct_entries * ring_entry_bytes(p)
    le_ct_entries = le_ciphertext_entries(p)
    return {
        "le_ciphertext_entries": le_ct_entries,
        "rbe_ciphertext_entries": ct_entries,
        "ciphertext_bytes": ct_bytes,
        "ciphertext_kib": ct_bytes / 1024.0,
        "ciphertext_mib": ct_bytes / (1024.0 ** 2),
        "pk_entries": p.n,
        "sk_entries": p.m,
        "witness_entries": p.ell * 2 * p.m,
        "commit_entries": commit_entries(p),
    }


def base_row(p: UnifiedParams, scheme: str) -> Dict[str, object]:
    return {
        "scheme": scheme,
        "N": p.N,
        "B": p.B,
        "ell": p.ell,
        "n": p.n,
        "m": p.m,
        "r": p.r_for_csv,
        "t": p.t_for_csv,
        "q_bits": p.q_bits,
        "d": p.d,
        "sigma_inf": p.sigma_inf,
        "short_min": p.short_min,
        "short_max": p.short_max,
        "short_range": p.short_range,
        "message_bits": p.message_bits,
        "ring_degree": p.ring_degree,
        "poly_mul_model": p.poly_mul_model,
    }
