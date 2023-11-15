import enum


class SymmetricKeyAlgorithm(enum.Enum):
    RSA = 0
    ECDSA = 1


class SigningAlgorithm(enum.Enum):
    RSA = 0
    ECDSA = 1
    HMAC = 2


class Header:
    algorithm: str
    claims: str

    def inject_new_claim(self):
        pass

    def __str__(self):
        pass


class Payload:
    claims: dict[str]

    def inject_new_claim(self):
        pass

    def __str__(self):
        pass


class Signature:

    def check_signature(self):
        pass

    def check_signature_kid(self):
        pass

    def crack_signature(self):
        pass

    def __str__(self):
        pass


class JWT:
    header: Header
    data: Payload
    signature: Signature

    def check_public_key_exploit(self):
        pass

    def tamper_with_token(self):
        pass

    def build_subclaim(self):
        pass

    def test_key(self):
        pass

    def validate_token(self):
        pass

    def __str__(self):
        pass


class JWKS(JWT):

    def build_jwks(self):
        pass

    def generate_jwks(self):
        pass

    def embed_jwks(self):
        pass

    def export_jwks(self):
        pass

    def parse_jwks(self):
        pass

    def get_keypair(self):
        pass

    def generate_symmetric_keypair(self, key_format: SymmetricKeyAlgorithm):
        pass

    def sign_token(self, signing_algorithm: SigningAlgorithm):
        pass

    def verify_token(self, signing_algorithm: SigningAlgorithm):
        pass

    def generate_public_key_from_jwks(self, key_format: SymmetricKeyAlgorithm):
        pass
