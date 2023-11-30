import base64
import hashlib
import hmac
import json
import logging
from typing import Union, Dict, Optional

import Cryptodome.Hash.SHA3_256
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pkcs1_15

from jwt_tool.JWK import JWK
from jwt_tool.JWKS import JWKS


class Header:
    """
    JSON Web Token (JWT) Header representation.

    Attributes:
        alg (str): The algorithm used for signing the token.
        typ (str): The type of the token, e.g., "JWT".
        kid (str): The key was used to sign the JWT, e.g.,
        custom_claims (Dict[str, Union[str, int, float]]): Custom claims added to the header.

    Methods:
        to_json: Converts the header to a JSON string.
        add_claim: Adds a custom claim to the header.
        encode: Encodes the header for use in a JWT.

    Example:
        header = JWTHeader(alg="HS256", typ="JWT")
        header.add_claim("custom_key", "custom_value")
        header_json = header.to_json()
    """
    algorithm: str
    typ: str
    claims: str

    def __init__(self, alg: str, typ: str = "JWT", custom_claims: Dict[str, Union[str, int, float]] = None):
        self.alg = alg
        self.typ = typ
        self.custom_claims = custom_claims or {}

    def add_claim(self, key: str, value: Union[str, int, float]):
        """Adds a custom claim to the header. If the claim already exists, it will be overridden."""
        self.custom_claims[key] = value

    def get_custom_claim(self, key):
        """Gets a claim from the payload. If claim does not exist, returns None"""
        return self.custom_claims.get(key, None)

    def to_json(self) -> bytes:
        """Converts the header to a JSON string."""
        header_dict = {
            "alg": self.alg,
            "typ": self.typ,
            **self.custom_claims  # Include custom claims as key-value pairs
        }
        return json.dumps(header_dict, separators=(",", ":")).encode("UTF-8")

    def urlsafe_b64encode(self):
        return base64.urlsafe_b64encode(self.to_json()).decode().strip('=')

    @classmethod
    def from_json(cls, json_string: str) -> "Header":
        """Creates a JWTHeader object from a JSON string."""
        header_dict = json.loads(json_string)
        return cls(alg=header_dict["alg"], typ=header_dict["typ"], **header_dict)

    def __str__(self) -> str:
        """String representation of the header."""
        return f"Header(alg={self.alg}, typ={self.typ}, custom_claims={self.custom_claims})"

    def __repr__(self) -> str:
        """Official string representation of the header."""
        return f"Header(alg={self.alg}, typ={self.typ}, custom_claims={self.custom_claims})"

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

    def add_claim(self, key: str, value: Union[str, int, float]):
        """Adds a custom claim to the payload. If the claim already exists, it will be overridden."""
        self.data[key] = value

    def get_claim(self, key):
        """Gets a claim from the payload. If claim does not exist, returns None"""
        return self.data.get(key, None)

    def to_json(self) -> bytes:
        """Converts the payload to a JSON string."""
        return json.dumps(self.data, separators=(",", ":")).encode("UTF-8")

    def urlsafe_b64encode(self):
        return base64.urlsafe_b64encode(self.to_json()).decode().strip('=')

    def __str__(self) -> str:
        """String representation of the payload."""
        return f"Payload(data={self.data})"

    def __repr__(self) -> str:
        """Official string representation of the payload."""
        return f"Payload(data={self.data})"

    def __eq__(self, other: "Payload") -> bool:
        """Equality comparison between two payloads."""
        return self.data == other.data


class Signature:
    """
    JSON Web Token (JWT) Signature representation.

    Attributes:
        key (bytes): The key used for signing.

    Methods:
        sign: Generates the signature for the given data.
        generate_hmac_signature: Generates HMAC signature for HMAC-based algorithms.
        generate_rsa_signature: Generates RSA signature for RSA-based algorithms.

    Example:
        signature = JWSSignature(key=b"secret_key", algorithm="HS256")
        token_signature = signature.sign(header_and_payload)
    """
    key: str
    algorithm: str

    def __init__(self, key: str, algorithm: str):
        self.key = key
        self.algorithm = algorithm

    def sign(self, header: str, payload: str) -> str:
        """Generates the signature for the given data."""
        # Concatenate encoded header and payload with a period
        data = header + '.' + payload

        if self.algorithm.startswith("HS"):
            digest = (hmac.new(self.key.encode("UTF-8"), data.encode("UTF-8"), "sha256")).digest()
            signature = base64.urlsafe_b64encode(digest).decode().strip('=')

            return signature

    @staticmethod
    def generate_hmac_signature(encoded_data: bytes, key: bytes) -> bytes:
        """Generates HMAC signature for HMAC-based algorithms."""
        return hmac.new(key, encoded_data, hashlib.sha256).digest()

    @staticmethod
    def generate_rsa_signature(encoded_data: bytes, private_key: Union[bytes, RSA.RsaKey]) -> bytes:
        """Generates RSA signature for RSA-based algorithms."""
        if isinstance(private_key, bytes):
            private_key = RSA.import_key(private_key)
        h = SHA256.new(encoded_data)
        signature = pkcs1_15.new(private_key).sign(h)
        return signature

    def __str__(self) -> str:
        """String representation of the Signature."""
        return f"Signature(key={self.key}, algorithm={self.algorithm})"


class JWT:
    """
    JSON Web Token (JWT) representation.

    Attributes:
        header (Header): The token header.
        payload (Payload): The token payload.
        signature (Signature): The token signature.

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

    def __init__(self, header: Header, payload: Payload, signature: Signature, jwks: Optional["JWKS"] = None):
        self.header = header
        self.payload = payload
        self.signature = signature
        self.jwks = jwks

    def verify(self, encoded_token: str, secret_key: str) -> bool:
        """
        Verifies the JWT token, as per RFC 7519#7.2
        If any of the listed steps fail, then the JWT is rejected.

        Args:
            secret_key:
            encoded_token:

        Returns:

        """
        if not encoded_token:
            return False

        # Verify that the JWT contains at least one period ('.') character.
        parts = encoded_token.split('.')

        # Ensure there are at least two parts (header and payload)
        if len(parts) < 2:
            logging.warning("Invalid JWT format. At least two parts (header and payload) are required.")
            return False

        header, payload = parts[:2]

        if len(parts) == 3:
            signature = parts[2]
            # Verify the signature using HMAC-SHA256
            computed_signature = hmac.new(secret_key.encode('utf-8'), f'{header}.{payload}'.encode('utf-8'), Cryptodome.Hash.SHA3_256.SHA3_256_Hash)
            expected_signature = self._base64url_decode(signature)

            if computed_signature.digest() == expected_signature:
                return True
            else:
                return False
        else:
            return True

    def get_key_from_jwks(self) -> Union[JWK, None]:
        """Retrieves the key from the JWKS based on the Key ID (kid)."""
        return self.jwks.get_key_by_kid(self.signature.kid)

    @staticmethod
    def _base64url_decode(encoded_string: str):
        # Add padding if necessary and then decode base64url
        padding = len(encoded_string) % 4
        if padding:
            encoded_string += '=' * (4 - padding)
        return base64.urlsafe_b64decode(encoded_string.encode('utf-8'))

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
