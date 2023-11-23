import enum
import pathlib

CONFIG_PATH = pathlib.Path(pathlib.Path.home() / ".config" / "jwt_tool")


class SymmetricKeyAlgorithm(enum.Enum):
    RSA = 0
    ECC = 1
    DSA = 2


class SigningAlgorithm(enum.Enum):
    RSA = 0
    ECC = 1
    HMAC = 2
