from pathlib import Path

import pytest
from Cryptodome.PublicKey import RSA, ECC

from jwt_tool.jot import JWK, SymmetricKeyAlgorithm, JWKS


@pytest.mark.usefixtures('rsa_public_key')
@pytest.mark.usefixtures('ecc_public_key')
class TestJWK:
    def test_determine_key_type_rsa(self, rsa_public_key, ecc_public_key):
        jwk = JWK(kid="rsa_key", public_key=rsa_public_key)
        assert jwk.kty == SymmetricKeyAlgorithm.RSA

    def test_determine_key_type_ecc(self, rsa_public_key, ecc_public_key):
        jwks = JWK(kid="ecc_key", public_key=ecc_public_key)
        assert jwks.kty == SymmetricKeyAlgorithm.ECC

    def test_determine_key_type_unknown(self, rsa_public_key, ecc_public_key):
        unknown_key = b'\x00\x01\x02\x03'  # Some arbitrary bytes
        with pytest.raises(Exception, match="Unknown key type"):
            jwks = JWK(kid="unknown", public_key=unknown_key)


def test_jwks_add_key():
    jwks = JWKS()
    assert len(jwks.keys) == 0

    jwk = JWK(kid="test_key", public_key="...")
    jwks.add_key(jwk)

    assert len(jwks.keys) == 1
    assert jwks.keys[0] == jwk


def test_jwks_get_key_by_kid():
    jwks = JWKS()
    jwk1 = JWK(kid="key1", public_key="...")
    jwk2 = JWK(kid="key2", public_key="...")
    jwk3 = JWK(kid="key3", public_key="...")

    jwks.add_key(jwk1)
    jwks.add_key(jwk2)
    jwks.add_key(jwk3)

    assert jwks.get_key_by_kid("key2") == jwk2
    assert jwks.get_key_by_kid("nonexistent_key") is None


def test_jwks_str():
    jwks = JWKS()
    jwk1 = JWK(kid="key1", public_key="...")
    jwk2 = JWK(kid="key2", public_key="...")

    jwks.add_key(jwk1)
    jwks.add_key(jwk2)

    expected_str = (
        "JSON Web Key Set (JWKS):\n"
        f"{str(jwk1)}\n"
        f"{str(jwk2)}\n"
    )

    assert str(jwks) == expected_str