import os
from pathlib import Path

from dotenvx_py import load_dotenv

from dotenvx_py.dotenvx import (
    encrypt_item,
    decrypt_item,
    read_public_key,
    read_private_key,
    dotenv_values,
    find_global_key_pairs,
)


def test_encrypt_item():
    pk_hex = "03053b200bd90daf426d593b1f28e738c7e87487ee45f865f706da320fb7bf0902"
    sk_hex = "d01f0c48aa665499d995d7769c4bda680992e2549fcd4ba144138d31d176462f"
    encrypted_text = encrypt_item(pk_hex, "hello")
    print(encrypted_text)
    plain_text = decrypt_item(sk_hex, encrypted_text)
    print(plain_text)


def test_load_dotenvx():
    load_dotenv()
    print(os.environ["KEY1"])


def test_load_values():
    entries = dotenv_values(".env")
    print(entries)


def test_read_pk():
    pk = read_public_key(".env")
    print(pk)


def test_read_sk():
    pk = read_private_key(None)
    print(pk)
    current_dir = Path.cwd()
    for parent in current_dir.parents:
        print(parent)


def test_global_key_paris():
    key_paris = find_global_key_pairs()
    print(key_paris)
