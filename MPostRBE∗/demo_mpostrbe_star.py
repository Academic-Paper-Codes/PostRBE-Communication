# demo_mpostrbe_star.py
from mpostrbe_star_core import (
    setup_mstar, keygen_mstar, register_mstar,
    encrypt_group_mstar, decrypt_group_mstar
)

def main():
    crs, pp, aux = setup_mstar(N_max=100, B=10, q=12289, n=4, m=6, t=8)


    recips = [12, 15, 19]  # same row when B=10
    users = []
    for uid in recips:
        u = keygen_mstar(uid, crs)
        users.append(u)
        register_mstar(u, crs, pp, aux)

    msg = b"hello MPostRBE* group (AEAD)"
    ct = encrypt_group_mstar(pp, crs, recips, msg)

    print("Recipients:", recips)
    for u in users:
        pt = decrypt_group_mstar(u, crs, aux, ct)
        print(f"user {u['user_id']} ->", pt == msg)

    # tamper wrapper for first recipient (flip one byte of tag)
    bad = dict(ct)
    bad_w = {k: dict(v) for k, v in ct["w"].items()}
    first_uid = recips[0]
    tag = bad_w[first_uid]["tag"]
    bad_w[first_uid]["tag"] = bytes([tag[0] ^ 1]) + tag[1:]
    bad["w"] = bad_w
    try:
        decrypt_group_mstar(users[0], crs, aux, bad)
        print("tamper(wrapper): UNEXPECTEDLY succeeded")
    except Exception as e:
        print("tamper(wrapper): OK ->", e.__class__.__name__)

    # tamper message c4 tag
    bad2 = dict(ct)
    p4 = dict(ct["c4_pack"])
    tag4 = p4["tag"]
    p4["tag"] = bytes([tag4[0] ^ 1]) + tag4[1:]
    bad2["c4_pack"] = p4
    try:
        decrypt_group_mstar(users[1], crs, aux, bad2)
        print("tamper(message): UNEXPECTEDLY succeeded")
    except Exception as e:
        print("tamper(message): OK ->", e.__class__.__name__)


if __name__ == "__main__":
    main()
