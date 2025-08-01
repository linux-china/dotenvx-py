import base64

from ecies.keys import PrivateKey, PublicKey
from ecies import encrypt, decrypt


def test_ecies():
    data = "hello world🌍".encode()
    sk = PrivateKey("secp256k1")
    sk_bytes = sk.secret
    pk_bytes = sk.public_key.to_bytes(True)
    encrypted_bytes = encrypt(pk_bytes, data)
    # base64 encrypted_bytes
    encrypted_base64 = base64.b64encode(encrypted_bytes).decode('utf-8')
    print(encrypted_base64)

    plain_text = decrypt(sk_bytes, encrypted_bytes).decode()
    print(plain_text)

def test_load_pk():
    pk = PublicKey.from_hex("secp256k1", "03053b200bd90daf426d593b1f28e738c7e87487ee45f865f706da320fb7bf0902")
    msg = "hello world🌍".encode()
    encrypted = encrypt(pk.to_bytes(True), msg)
    print(base64.b64encode(encrypted).decode('utf-8'))
