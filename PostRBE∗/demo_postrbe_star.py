# demo_postrbe_star.py
from postrbe_star_core import (
    setup_star, keygen_star, register_star, update_star,
    encrypt_star, decrypt_star
)

def main():
    # parameters (same tiny toy params as base demo)
    crs, pp, aux = setup_star(security_param=128, N_max=100, q=12289, n=4, m=6, t=8)

    # one user
    user_id = 7
    user = keygen_star(user_id, crs)
    register_star(user, crs, pp, aux)

    # encrypt/decrypt
    msg = b"hello PostRBE* (AEAD)"
    ct = encrypt_star(pp, crs, user_id, msg)
    pt = decrypt_star(user, crs, aux, ct)

    print("original:", msg)
    print("decrypted:", pt)
    print("equal?   ", msg == pt)

    # quick tamper test (should fail)
    try:
        bad = dict(ct)
        bad["tag"] = bytes([ct["tag"][0]^1]) + ct["tag"][1:]
        decrypt_star(user, crs, aux, bad)
        print("tamper test: UNEXPECTEDLY succeeded")
    except Exception as e:
        print("tamper test: OK ->", (str(e) or e.__class__.__name__))

if __name__ == "__main__":
    main()
