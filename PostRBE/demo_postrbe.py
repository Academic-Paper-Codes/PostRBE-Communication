# demo_postrbe.py
from postrbe_core import setup, keygen, register, encrypt, decrypt


def main():
    # 1. 初始化系统
    crs, pp, aux = setup(security_param=128, N_max=100)

    # 2. 生成并注册一个用户（比如 id = 7）
    user_id = 7
    user = keygen(user_id, crs)
    pp, aux = register(user, crs, pp, aux)

    # 3. 加密一条消息
    message = b"hello PostRBE! this is a test message."
    ct = encrypt(pp, crs, user_id, message)

    # 4. 解密
    pt = decrypt(user, crs, aux, ct)

    print("original:", message)
    print("decrypted:", pt)
    print("equal?   ", message == pt)


if __name__ == "__main__":
    main()
