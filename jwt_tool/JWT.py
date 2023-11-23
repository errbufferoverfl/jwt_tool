import json
from typing import Union, Dict

from jwt_tool.JWKS import JWKS


class Header:
    """
    JSON Web Token (JWT) Header representation.

    Attributes:
        alg (str): The algorithm used for signing the token.
        typ (str): The type of the token (e.g., "JWT").
        custom_claims (Dict[str, Union[str, int, float]]): Custom claims added to the header.

    Methods:
        to_json: Converts the header to a JSON string.
        add_claim: Adds a custom claim to the header.

    Example:
        header = JWTHeader(alg="HS256", typ="JWT")
        header.add_claim("custom_key", "custom_value")
        header_json = header.to_json()
    """
    algorithm: str
    type: str
    claims: str

    def __init__(self, alg: str, typ: str):
        self.alg = alg
        self.typ = typ
        self.custom_claims = {}

    def inject_new_claim(self, key: str, value: Union[str, int, float]):
        """Adds a custom claim to the header."""
        self.custom_claims[key] = value

    def to_json(self) -> str:
        """Converts the header to a JSON string."""
        return json.dumps({"alg": self.alg, "typ": self.typ})

    def __str__(self) -> str:
        """String representation of the header."""
        return f"JWTHeader(alg={self.alg}, typ={self.typ}, custom_claims={self.custom_claims})"

    def __repr__(self) -> str:
        """Official string representation of the header."""
        return f"JWTHeader(alg={self.alg}, typ={self.typ}, custom_claims={self.custom_claims})"

    def __eq__(self, other: "Header") -> bool:
        """Equality comparison between two headers."""
        return (
                self.alg == other.alg
                and self.typ == other.typ
                and self.custom_claims == other.custom_claims
        )


class Payload:
    """
    JSON Web Token (JWT) Payload representation.

    Attributes:
        data (Dict[str, Union[str, int, float]]): The payload data.

    Methods:
        to_json: Converts the payload to a JSON string.
        add_claim: Adds a custom claim to the payload.

    Dunder Methods:
        __str__: String representation of the payload.
        __repr__: Official string representation of the payload.
        __eq__: Equality comparison between two payloads.

    Example:
        payload = JWTPayload(data={"user_id": 123, "username": "john_doe"})
        payload.add_claim("custom_key", "custom_value")
        payload_json = payload.to_json()
    """
    data: dict[str]

    def __init__(self, data: Dict[str, Union[str, int, float]]):
        self.data = data

    def inject_new_claim(self, key: str, value: Union[str, int, float]):
        """Adds a custom claim to the payload."""
        self.data[key] = value

    def __str__(self) -> str:
        """String representation of the payload."""
        return f"JWTPayload(data={self.data})"

    def __repr__(self) -> str:
        """Official string representation of the payload."""
        return f"JWTPayload(data={self.data})"

    def __eq__(self, other: "Payload") -> bool:
        """Equality comparison between two payloads."""
        return self.data == other.data

    def to_json(self) -> str:
        """Converts the payload to a JSON string."""
        return json.dumps(self.data)


class Signature:
    """
    JSON Web Token (JWT) Signature representation.

    Attributes:
        key (bytes): The key used for signing.
        algorithm (str): The signing algorithm (e.g., "HS256").

    Methods:
        sign: Generates the signature for the given data.

    Example:
        signature = JWSSignature(key=b"secret_key", algorithm="HS256")
        token_signature = signature.sign(header_and_payload)
    """
    def __init__(self, key: bytes, algorithm: str):
        self.key = key
        self.algorithm = algorithm

    def check_signature(self):
        pass

    def check_signature_kid(self):
        pass

    def crack_signature(self):
        pass

    def __str__(self):
        pass


class JWT:
    """
    JSON Web Token (JWT) representation.

    Attributes:
        header (JWTHeader): The token header.
        payload (JWTPayload): The token payload.
        signature (JWSSignature): The token signature.

    Methods:
        encode: Generates the complete JWT by encoding header, payload, and signature.
        verify: Verifies the integrity of a JWT.

    Dunder Methods:
        __str__: String representation of the JWT.
        __repr__: Official string representation of the JWT.
        __eq__: Equality comparison between two JWTs.

    Example:
        jwt = JWT(header=JWTHeader(alg="HS256", typ="JWT"),
                  payload=JWTPayload(data={"user_id": 123, "username": "john_doe"}),
                  signature=JWSSignature(key=b"secret_key", algorithm="HS256"))
        encoded_token = jwt.encode()
        is_valid = jwt.verify(encoded_token)
        jwt.update_header_claim("sub", "U12345")
    """
    header: Header
    data: Payload
    signature: Signature

    jwks: JWKS

    def __init__(self, header: Header, payload: Payload, signature: Signature, jwks: JWKS):
        self.header = header
        self.payload = payload
        self.signature = signature
        self.jwks = jwks

    def encode(self) -> str:
        """Generates the encoded JWT token."""
        # Implementation of encoding logic

    def verify(self, encoded_token: str) -> bool:
        """Verifies the JWT token."""
        # Implementation of verification logic
        key = self.get_key_from_jwks()
        # Rest of the verification logic

    def get_key_from_jwks(self) -> Union[JWK, None]:
        """Retrieves the key from the JWKS based on the Key ID (kid)."""
        return self.jwks.get_key_by_kid(self.signature.kid)

    def check_public_key_exploit(self):
        pass

    def tamper_with_token(self):
        pass

    def update_header_claim(self, claim_key: str, claim_value: str):
        """Updates a claim in the JWT header."""
        setattr(self.header, claim_key, claim_value)

    def test_key(self):
        pass

    def __str__(self) -> str:
        """String representation of the JWT."""
        return f"JWT(header={self.header}, payload={self.payload}, signature={self.signature})"

    def __repr__(self) -> str:
        """Official string representation of the JWT."""
        return f"JWT(header={repr(self.header)}, payload={repr(self.payload)}, signature={repr(self.signature)})"

    def __eq__(self, other: "JWT") -> bool:
        """Equality comparison between two JWTs."""
        return (
                self.header == other.header
                and self.payload == other.payload
                and self.signature == other.signature
        )
