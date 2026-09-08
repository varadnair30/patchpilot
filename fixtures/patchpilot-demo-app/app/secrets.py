import os

from cryptography.fernet import Fernet

_key = os.environ.get("DEMO_FERNET_KEY") or Fernet.generate_key()
_fernet = Fernet(_key)


def seal(text: str) -> str:
    return _fernet.encrypt(text.encode()).decode()


def unseal(token: str) -> str:
    return _fernet.decrypt(token.encode()).decode()
