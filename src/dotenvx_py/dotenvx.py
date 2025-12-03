import base64
import json
from typing import (
    Optional,
    Union,
    IO,
    Dict,
    Any,
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
        override=True,
    ).set_as_environment_variables()


def dotenv_values(
    dotenv_path: Optional[StrPath] = None,
    stream: Optional[IO[str]] = None,
    verbose: bool = False,
    interpolate: bool = True,
    encoding: Optional[str] = "utf-8",
) -> dict[str, Optional[str]]:
    entries = dotenv.dotenv_values(dotenv_path, stream, verbose, interpolate, encoding)
    public_key: str = None
    private_key: str = None
    for key, value in entries.items():
        if key.startswith("DOTENV_PUBLIC_KEY"):
            public_key = value
    if public_key:
        store = find_global_key_pairs()
        if public_key in store:
            private_key = trim_private_key(store[public_key])
    if private_key is None:
        profile = read_profile(dotenv_path)
        private_key = read_private_key(profile)
    for key, value in entries.items():
        if value.startswith("encrypted:"):
            entries[key] = decrypt_item(private_key, value)
    return entries


def decrypt_entries(
    env_data: dict[str, Any], profile: Optional[str] = None
) -> dict[str, Any]:
    if profile:
        public_key = env_data[f"DOTENV_PUBLIC_KEY_{profile.upper()}"]
    else:
        public_key = env_data["DOTENV_PUBLIC_KEY"]
    private_key = find_private_key(public_key, profile)
    if private_key:
        # iterator env_date and decrypt value prefix with encrypted:
        for key, value in env_data.items():
            if isinstance(value, str) and value.startswith("encrypted:"):
                decrypted_value = decrypt_item(private_key, value)
                env_data[key] = decrypted_value
    return env_data


def encrypt_item(public_key_hex: str, text: str) -> str:
    """
    encrypt item by public key and text.
    :param public_key_hex: public key hex
    :param text: text to encrypt
    :return: encrypted text with base64 encoded and prefix "encrypted:
    """
    pk = PublicKey.from_hex(
        "secp256k1",
        public_key_hex,
    )
    encrypted = encrypt(pk.to_bytes(True), text.encode("utf-8"))
    return "encrypted:" + base64.b64encode(encrypted).decode("utf-8")


def decrypt_item(private_key_hex: str, encrypted_text: str) -> str:
    """
    decrypt item by private key and encrypted text.
    :param private_key_hex: private key hex
    :param encrypted_text: encrypted text with base64 encoded
    :return:
    """
    sk = PrivateKey.from_hex(
        "secp256k1",
        private_key_hex,
    )
    if encrypted_text.startswith("encrypted:"):
        encrypted_text = encrypted_text.replace("encrypted:", "")
    encrypted_bytes = base64.b64decode(encrypted_text)
    text_bytes = decrypt(sk.secret, encrypted_bytes)
    return text_bytes.decode("utf-8")


def read_profile(env_file: Optional[StrPath] = None) -> Optional[str]:
    """
    read profile from environment variables or .env file name.
    :param env_file: env file path
    :return: profile name
    """
    env_key_names = ["NODE_ENV", "RUN_ENV", "APP_ENV", "SPRING_PROFILES_ACTIVE"]
    for env_key_name in env_key_names:
        if env_key_name in os.environ:
            return os.environ[env_key_name]
    if env_file:
        file_name = env_file
        if "/" in env_file:
            file_name = env_file.split("/")[-1]
        elif "\\" in env_file:
            file_name = env_file.split("\\")[-1]
        if file_name.startswith(".env."):
            return file_name[5:]
    return None


def read_public_key(env_file: str) -> Optional[str]:
    """
    read public key from .env file.
    :param env_file: env file path
    :return: public key
    """
    file_text = Path(env_file).read_text()
    for line in file_text.splitlines():
        if line.startswith("DOTENV_PUBLIC_KEY"):
            return line.split("=")[1].strip().strip('"')
    return None


def find_private_key(
    public_key: Optional[str] = None, profile_name: Optional[str] = None
) -> Optional[str]:
    private_key: str = None
    if public_key:
        store = find_global_key_pairs()
        if public_key in store:
            private_key = trim_private_key(store[public_key])
    if private_key is None:
        private_key = read_private_key(profile_name)
    return private_key


def read_private_key(profile: Optional[StrPath] = None) -> Optional[str]:
    """
    read private key by profile name, and value is from environment or .env.keys file.
    :param profile: profile name
    :return: private key
    """
    if profile is None:
        sk_key_name = "DOTENV_PRIVATE_KEY"
    else:
        sk_key_name = f"DOTENV_PRIVATE_KEY_{profile.upper()}"
    env_key_file = find_env_keys_file(Path.cwd())
    entries = dotenv.dotenv_values(env_key_file)
    if sk_key_name in entries:
        return trim_private_key(entries[sk_key_name])
    else:
        return trim_private_key(os.environ.get(sk_key_name))


def trim_private_key(private_key: str) -> str:
    if private_key and "{" in private_key:
        return private_key[0 : private_key.index("{")]
    return private_key


def find_env_keys_file(current_dir: Path) -> Optional[Path]:
    """
    find .env.keys file in give path and its parent directories.
    :param current_dir: current directory to start searching
    :return: .env.keys file path
    """
    if (current_dir / env_keys_file_name).exists():
        return current_dir / env_keys_file_name
    # find .env.keys file in current directory or parent directories up to root
    for parent in current_dir.parents:
        env_keys_file = parent / env_keys_file_name
        if env_keys_file.exists():
            return env_keys_file
    return None


def find_global_key_pairs() -> dict[str, str]:
    # read $HOME/.dotenvx/.env.keys.json file
    home_dir = Path.home()
    env_keys_file = home_dir / ".dotenvx" / ".env.keys.json"
    if env_keys_file.exists():
        json_text = env_keys_file.read_text()
        store: dict = json.loads(json_text)
        if "version" in store and "keys" in store:
            store = store["keys"]
        pairs = {}
        for public_key, key_pair in store.items():
            pairs[public_key] = key_pair["private_key"]
        return pairs
    return {}
