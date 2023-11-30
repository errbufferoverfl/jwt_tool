from pathlib import Path

import pytest

from jwt_tool.JWT import Header


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
