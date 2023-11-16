import pytest
from Cryptodome.PublicKey import RSA, ECC

from jwt_tool.jot import JWK, SymmetricKeyAlgorithm


def test_determine_key_type_rsa():
    rsa_public_key = RSA.generate(2048)
    rsa_public_key = rsa_public_key.export_key(format="PEM")
    jwks = JWK("12345", rsa_public_key)

    print(jwks.__str__())

    assert jwks.kty == SymmetricKeyAlgorithm.RSA


def test_determine_key_type_ecc():
    ecc_key = ECC.generate(curve='P-256')
    ecc_public_key = ecc_key.export_key(format="PEM")
    jwks = JWK(ecc_public_key)

    assert jwks.kty == SymmetricKeyAlgorithm.ECC


def test_determine_key_type_unknown():
    unknown_key = b'\x00\x01\x02\x03'  # Some arbitrary bytes
    with pytest.raises(Exception, match="Unknown key type"):
        jwks = JWK(unknown_key)
