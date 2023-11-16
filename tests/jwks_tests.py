import pytest

from jwt_tool.jot import JWKS, JWK


@pytest.mark.usefixtures('rsa_public_key')
class TestJWKS:
    def test_jwks_add_key(self, rsa_public_key):
        jwks = JWKS()
        assert len(jwks.keys) == 0

        jwk = JWK(kid="test_key", public_key=rsa_public_key)
        jwks.add_key(jwk)

        assert len(jwks.keys) == 1
        assert jwks.keys[0] == jwk

    def test_jwks_get_key_by_kid(self, rsa_public_key):
        jwks = JWKS()
        jwk1 = JWK(kid="key1", public_key=rsa_public_key)
        jwk2 = JWK(kid="key2", public_key=rsa_public_key)
        jwk3 = JWK(kid="key3", public_key=rsa_public_key)

        jwks.add_key(jwk1)
        jwks.add_key(jwk2)
        jwks.add_key(jwk3)

        assert jwks.get_key_by_kid("key2") == jwk2
        assert jwks.get_key_by_kid("nonexistent_key") is None

    def test_jwks_str(self, rsa_public_key):
        jwks = JWKS()
        jwk1 = JWK(kid="key1", public_key=rsa_public_key)
        jwk2 = JWK(kid="key2", public_key=rsa_public_key)

        jwks.add_key(jwk1)
        jwks.add_key(jwk2)

        expected_str = (
            "JSON Web Key Set (JWKS):\n"
            f"{str(jwk1)}\n"
            f"{str(jwk2)}\n"
        )

        assert str(jwks) == expected_str
