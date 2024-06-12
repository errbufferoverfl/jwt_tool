import pytest

from jwt_tool import SymmetricKeyAlgorithm
from jwt_tool.JWK import JWK


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
