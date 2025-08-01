import base64
from typing import (
    Optional,
    Union,
    IO,
    Dict,
)
import os
from pathlib import Path


from ecies.keys import PrivateKey, PublicKey
from ecies import encrypt, decrypt
import dotenv

StrPath = Union[str, "os.PathLike[str]"]

env_keys_file_name = ".env.keys"


class DotEnvx:
    def __init__(
        self,
        dotenv_path: Optional[StrPath],
        stream: Optional[IO[str]] = None,
        verbose: bool = False,
        encoding: Optional[str] = None,
        interpolate: bool = True,
        override: bool = True,
    ) -> None:
        self.dotenv_path: Optional[StrPath] = dotenv_path
        self.stream: Optional[IO[str]] = stream
        self._dict: Optional[Dict[str, Optional[str]]] = None
        self.verbose: bool = verbose
        self.encoding: Optional[str] = encoding
        self.interpolate: bool = interpolate
        self.override: bool = override
        self.entries: Optional[dict[str, Optional[str]]] = None

    def dict(self) -> Dict[str, Optional[str]]:
        if self.entries is None:
            self.entries = dotenv_values(self.dotenv_path, self.stream, self.encoding)
        return self.entries

    def set_as_environment_variables(self) -> bool:
        if not self.dict():
            return False
        for k, v in self.dict().items():
            if k in os.environ and not self.override:
                continue
            if v is not None:
                os.environ[k] = v
        return True

    def get(self, key: str) -> Optional[str]:
        data = self.dict()
        if key in data:
            return data[key]
        return None


def load_dotenv(
    dotenv_path: Optional[StrPath] = None,
    stream: Optional[IO[str]] = None,
    verbose: bool = False,
    interpolate: bool = True,
    encoding: Optional[str] = "utf-8",
) -> bool:
    return DotEnvx(
        dotenv_path=dotenv_path,
        stream=stream,
        verbose=verbose,
        interpolate=interpolate,
        encoding=encoding,
    ).set_as_environment_variables()


def dotenv_values(
    dotenv_path: Optional[StrPath] = None,
    stream: Optional[IO[str]] = None,
    verbose: bool = False,
    interpolate: bool = True,
    encoding: Optional[str] = "utf-8",
) -> dict[str, Optional[str]]:
    profile = read_profile(dotenv_path)
    sk_hex = read_sk(profile)
    entries = dotenv.dotenv_values(dotenv_path, stream, verbose, interpolate, encoding)
    for key, value in entries.items():
        if value.startswith("encrypted:"):
            entries[key] = decrypt_item(sk_hex, value)
    return entries


def encrypt_item(pk_hex: str, text: str) -> str:
    pk = PublicKey.from_hex(
        "secp256k1",
        pk_hex,
    )
    encrypted = encrypt(pk.to_bytes(True), text.encode("utf-8"))
    return "encrypted:" + base64.b64encode(encrypted).decode("utf-8")


def decrypt_item(sk_hex: str, encrypted_text: str) -> str:
    sk = PrivateKey.from_hex(
        "secp256k1",
        sk_hex,
    )
    if encrypted_text.startswith("encrypted:"):
        encrypted_text = encrypted_text.replace("encrypted:", "")
    encrypted_bytes = base64.b64decode(encrypted_text)
    text_bytes = decrypt(sk.secret, encrypted_bytes)
    return text_bytes.decode("utf-8")


def read_profile(env_file: Optional[StrPath] = None) -> Optional[str]:
    if env_file is None:
        return None
    env_key_names = ["NODE_ENV", "RUN_ENV", "APP_ENV", "SPRING_PROFILES_ACTIVE"]
    for env_key_name in env_key_names:
        if env_key_name in os.environ:
            return os.environ[env_key_name]
    file_name = env_file
    if "/" in env_file:
        file_name = env_file.split("/")[-1]
    elif "\\" in env_file:
        file_name = env_file.split("\\")[-1]
    if file_name.startswith(".env."):
        return file_name[5:]
    return None


def read_pk(env_file: str) -> Optional[str]:
    file_text = Path(env_file).read_text()
    for line in file_text.splitlines():
        if line.startswith("DOTENV_PUBLIC_KEY"):
            return line.split("=")[1].strip().strip('"')
    return None


def read_sk(profile: Optional[StrPath] = None) -> Optional[str]:
    if profile is None:
        sk_key_name = "DOTENV_PRIVATE_KEY"
    else:
        sk_key_name = f"DOTENV_PRIVATE_KEY_{profile.upper()}"
    env_key_file = find_env_keys_file(Path.cwd())
    entries = dotenv.dotenv_values(env_key_file)
    if sk_key_name in entries:
        return entries[sk_key_name]
    else:
        return os.environ.get(sk_key_name)


def find_env_keys_file(path: Path) -> Optional[Path]:
    if (path / env_keys_file_name).exists():
        return path / env_keys_file_name
    # find .env.keys file in current directory or parent directories up to root
    for parent in path.parents:
        env_keys_file = parent / env_keys_file_name
        if env_keys_file.exists():
            return env_keys_file
    return None
