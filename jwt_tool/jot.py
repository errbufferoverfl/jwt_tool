import base64
import enum
import json
from typing import Union, List, Dict

from Cryptodome.PublicKey import RSA, ECC


class SymmetricKeyAlgorithm(enum.Enum):
    RSA = 0
    ECC = 1
    DSA = 2


class SigningAlgorithm(enum.Enum):
    RSA = 0
    ECC = 1
    HMAC = 2


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


class JWK:
    """
    JSON Web Key (JWK) is a set of keys containing public keys used to verify JSON Web Tokens (JWTs),
    issued by an Authorization Server and signed using the RS256 signing algorithm.

    Each property in the key is defined by the JWK specification (RFC 7517 Section 4) or,
    for algorithm-specific properties, in RFC 7518.

    Attributes:
        kid (str): The unique identifier for the key.
        use (str): How the key was meant to be used; "sig" represents the signature.

    Public Key Attributes:
        n (bytes): The modulus for the RSA public key.
        e (bytes): The exponent for the RSA public key.

    Algorithm-Specific Attribute:
        alg (str): The specific cryptographic algorithm used with the key.

    x.509 Certificate Attributes:
        x5c (list): The x.509 certificate chain. The first entry is the certificate to use for token verification,
                   and other certificates can be used to verify this first certificate.
        x5t (str): The thumbprint of the x.509 certificate (SHA-1 thumbprint).

    Methods:
        __init__: Initializes a JWK object.
    """

    def __init__(self, kid: str, public_key: Union[str, bytes], use: str = "sig"):
        """
        Initializes a JWK object.

        Args:
            kid (str): The unique identifier for the key.
            public_key (Union[str, bytes]): A str or bytes representation of a 'PEM' format public key.
            use (str): How the key was meant to be used; "sig" represents the signature. Default is "sig".

        Returns:
            None
        """
        self.kid = kid
        self.use = use

        self._guess_key_type(public_key)
        self.n = self._key
        self.e = self._key
        self.alg = ""
        self.x5c = []
        self.x5t = ""

    @property
    def n(self) -> str:
        """
        The public RSA modulus

        Returns:
            bytes representing the RSA modulus of the public key
        """
        return str(self._n.decode("UTF-8").rstrip("="))

    @n.setter
    def n(self, value: Union[str, bytes]):
        """
        Sets the public RSA modulus.

        Args:
            value (Union[str, bytes]): A str or bytes representation of a 'PEM' format public key.

        Returns:
            None
        """
        if self.kty is SymmetricKeyAlgorithm.RSA:
            # Assuming 'value' represents an RSA key object with a 'n' attribute
            self._n = base64.urlsafe_b64encode(value.n.to_bytes(256, byteorder="big"))

    @property
    def e(self) -> str:
        """
        Gets the public RSA exponent.

        This property returns the public RSA exponent as a string. The exponent must be an odd positive integer,
        typically a small number with very few ones in its binary representation.

        The FIPS standard requires the public exponent to be at least 65537 (the default).

        Returns:
            str: A string representing the public RSA exponent.
        """
        return self._e.decode("UTF-8")

    @e.setter
    def e(self, value: Union[str | bytes]):
        """
        Public RSA exponent. It must be an odd positive integer. It is typically a small number with very few ones
        in its binary representation.

        The FIPS standard requires the public exponent to be at least 65537 (the default).

        Args:
            value (Union[str, bytes]): A str or bytes representation of a 'PEM' format public key

        Returns:
            None
        """
        if self.kty is SymmetricKeyAlgorithm.RSA:
            self._e = base64.urlsafe_b64encode(value.e.to_bytes(3, byteorder="big"))

    def _guess_key_type(self, public_key: bytes):
        """
        Guesses the key type based on the provided public key and sets the internal key and key type attributes.

        Args:
            public_key (bytes): The public key in bytes format.

        Returns:
            None

        Raises:
            TypeError: If the key type cannot be determined or if the provided public key is not valid for any supported
                       key type (RSA, ECC).
        """
        try:
            rsa_key = RSA.importKey(public_key)
            self._key = rsa_key
            self.kty = SymmetricKeyAlgorithm.RSA
        except (ValueError, TypeError):
            try:
                ecc_key = ECC.import_key(public_key)
                self._key = ecc_key
                self.kty = SymmetricKeyAlgorithm.ECC
            except (ValueError, TypeError):
                raise TypeError("Unknown key type")

    def __str__(self):
        """
        Returns a plain text representation of the JWK.

        Returns:
            str: Plain text representation of the JWK.
        """
        jwk_str = f"JWK Information:\n"
        jwk_str += f"  kid: {self.kid}\n"
        jwk_str += f"  use: {self.use}\n"

        if hasattr(self, '_key'):
            jwk_str += f"  n: {base64.urlsafe_b64encode(self._key.n.to_bytes(256, byteorder='big')).decode('utf-8')}\n"
            jwk_str += f"  e: {base64.urlsafe_b64encode(self._key.e.to_bytes(4, byteorder='big')).decode('utf-8')}\n"

        jwk_str += f"  alg: {self.alg}\n"
        jwk_str += f"  x5c: {self.x5c}\n"
        jwk_str += f"  x5t: {self.x5t}\n"

        return jwk_str

    def __repr__(self):
        return f"JWK(kid={self.kid}, use={self.use}, alg={self.alg}, x5c={self.x5c}, x5t={self.x5t})"

    def __eq__(self, other):
        if isinstance(other, JWK):
            return (
                    self.kid == other.kid and
                    self.use == other.use and
                    self.alg == other.alg and
                    self.x5c == other.x5c and
                    self.x5t == other.x5t
            )
        return False

    def __ne__(self, other):
        return not self.__eq__(other)


class JWKS:
    """
    JSON Web Key Set (JWKS) representation.

    Attributes:
        keys (List[JWK]): List of JSON Web Keys in the set.

    Methods:
        add_key: Adds a JSON Web Key to the set.
        get_key_by_kid: Retrieves a key from the set based on the Key ID (kid).
        __str__: Returns a plain text representation of the JWKS.
    """

    def __init__(self, keys: List[JWK] = None):
        """
        Initializes a JWKS object.

        Args:
            keys (List[JWK]): List of JSON Web Keys. Defaults to an empty list.

        Returns:
            None
        """
        self.keys = keys or []

    def add_key(self, key: JWK):
        """
        Adds a JSON Web Key to the set.

        Args:
            key (JWK): The JSON Web Key to add.

        Returns:
            None
        """
        self.keys.append(key)

    def get_key_by_kid(self, kid: str) -> Union[JWK, None]:
        """
        Retrieves a key from the set based on the Key ID (kid).

        Args:
            kid (str): The Key ID (kid) to look for.

        Returns:
            Union[JWK, None]: The matching key if found, or None if not found.
        """
        for key in self.keys:
            if key.kid == kid:
                return key
        return None

    def __str__(self):
        """
        Returns a plain text representation of the JWKS.

        Returns:
            str: Plain text representation of the JWKS.
        """
        jwks_str = "JSON Web Key Set (JWKS):\n"
        for key in self.keys:
            jwks_str += str(key) + "\n"
        return jwks_str


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
