from pathlib import Path

import pytest

from jwt_tool.JWT import Header, JWT, Payload, SigningConfig


@pytest.fixture
def rsa_public_key() -> str:
    rsa_key_path = Path("data/rsa_public_key.pem")
    with open(rsa_key_path, "rb") as file:
        return file.read().decode("UTF-8")


@pytest.fixture
def ecc_public_key() -> str:
    ecc_key_path = Path("data/ecc_public_key.pem")
    with open(ecc_key_path, "rb") as file:
        return file.read().decode("UTF-8")


@pytest.fixture
def valid_jwt_object() -> JWT:
    header = Header("HS256", "JWT")
    payload = Payload({"iss": "joe", "exp": 1300819380, "http://example.com/is_root": True})
    signature = SigningConfig("password", "HS256")

    jwt = JWT(header, payload, signature)
    jwt.sign()

    return jwt


@pytest.fixture
def valid_jwt_string() -> str:
    path = Path("data/valid_jwt.txt")
    with open(path, "r") as file:
        return file.read()


@pytest.fixture
def valid_jwt_no_sig_string() -> str:
    path = Path("data/valid_jwt_no_sig.txt")
    with open(path, "r") as file:
        return file.read()


@pytest.fixture
def invalid_jwt_no_header() -> str:
    path = Path("data/invalid_jwt_no_header.txt")
    with open(path, "r") as file:
        return file.read()


@pytest.fixture
def invalid_jwt_no_payload() -> str:
    path = Path("data/invalid_jwt_no_payload.txt")
    with open(path, "r") as file:
        return file.read()