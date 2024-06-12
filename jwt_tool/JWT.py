import base64
import hmac
import json
import logging
from datetime import datetime, timezone
from typing import Union, Dict, Optional

from jwt_tool.JWK import JWK
from jwt_tool.JWKS import JWKS


class Header:
    """
    JSON Web Token (JWT) Header representation.

    Attributes:
        alg (str): The algorithm used for signing the token.
        typ (str): The type of the token, e.g., "JWT".
        kid (str): The key was used to sign the JWT.
        custom_claims (Dict[str, Union[str, int, float]]): Custom claims added to the header.

    Methods:
        add_claim: Adds a custom claim to the header.
        get_custom_claim: Gets a claim from the payload.
        to_json: Converts the header to a JSON string.
        from_json: Creates a Header object from a JSON string.
        encode: Encodes the header for use in a JWT.
        diff_claims: Compares the custom claims of two Header instances and returns the missing or added claims.
        get_provided_header: Returns the value of the private provided_header attribute.
        set_provided_header: Sets the value of the private provided_header attribute.

    Example:
        header = Header(alg="HS256", typ="JWT")
        header.add_claim("custom_key", "custom_value")
        header_json = header.to_json()
    """

    def __init__(self, alg: str, typ: str = "JWT", custom_claims: Dict[str, Union[str, int, float]] = None):
        self.alg = alg
        self.typ = typ
        self.custom_claims = custom_claims or {}
        self._provided_header = None  # Private attribute
        logging.debug(f"Initialized Header with alg={alg}, typ={typ}, custom_claims={self.custom_claims}")

    def add_claim(self, key: str, value: Union[str, int, float]):
        """Adds a custom claim to the header. If the claim already exists, it will be overridden."""
        self.custom_claims[key] = value
        logging.debug(f"Added custom claim to Header: {key}={value}")

    def get_custom_claim(self, key):
        """Gets a claim from the payload. If claim does not exist, returns None"""
        return self.custom_claims.get(key, None)

    def to_json(self) -> bytes:
        """Converts the header to a JSON byte string."""
        header_dict = {
            "alg": self.alg,
            "typ": self.typ,
            **self.custom_claims  # Include custom claims as key-value pairs
        }
        return json.dumps(header_dict, separators=(",", ":")).encode("utf8")

    @classmethod
    def from_json(cls, json_string: str) -> "Header":
        """Creates a Header object from a JSON string."""
        header_dict = json.loads(json_string)
        logging.debug(f"Decoded Header from JSON: {header_dict}")
        return cls(**header_dict)

    def encode(self) -> str:
        """Returns a base64url-encoded string with padding removed."""
        return base64.urlsafe_b64encode(self.to_json()).decode().strip('=')

    def diff_claims(self, other: "Header") -> Dict[str, list[str]]:
        """
        Compares the custom claims of two Header instances and returns the missing or added claims.

        Args:
            other (Header): Another instance of Header for comparison.

        Returns:
            Dict[str, list[str]]: A dictionary containing missing or added claims.
        """
        self_claims = set(self.custom_claims.keys())
        other_claims = set(other.custom_claims.keys())

        missing_claims = self_claims - other_claims
        added_claims = other_claims - self_claims

        diff_result = {"missing_claims": list(missing_claims), "added_claims": list(added_claims)}
        logging.debug(f"Difference in custom claims: {diff_result}")

        return diff_result

    def get_provided_header(self):
        """Returns the value of the private provided_header attribute."""
        return self._provided_header

    def set_provided_header(self, value):
        """Sets the value of the private provided_header attribute."""
        self._provided_header = value
        logging.debug(f"Set provided header: {value}")

    provided_header = property(get_provided_header, set_provided_header)

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
        add_claim: Adds a custom claim to the payload.
        get_claim: Gets a claim from the payload.
        to_json: Converts the payload to a JSON formatted byte string.
        from_json: Creates a Payload object from a JSON string.
        encode: Returns a base64url-encoded string with padding removed.
        diff_claims: Compares the custom claims of two Payload instances and returns the missing or added claims.
        validate_claims: Validates JWT claims such as "exp" (expiration time), "iat" (issued at), and "nbf" (not before).
        get_provided_payload: Returns the value of the private provided_payload attribute.
        set_provided_payload: Sets the value of the private provided_payload attribute.

    Dunder Methods:
        __str__: String representation of the payload.
        __repr__: Official string representation of the payload.
        __eq__: Equality comparison between two payloads.

    Example:
        payload = Payload(data={"user_id": 123, "username": "john_doe"})
        payload.add_claim("custom_key", "custom_value")
        payload_json = payload.to_json()
    """

    def __init__(self, data: Dict[str, Union[str, int, float]]):
        self.data = data
        self._provided_payload = None  # Private attribute
        logging.debug(f"Initialized Payload with data={data}")

    def add_claim(self, key: str, value: Union[str, int, float]):
        """Adds a custom claim to the payload. If the claim already exists, it will be overridden."""
        self.data[key] = value
        logging.debug(f"Added custom claim to Payload: {key}={value}")

    def get_claim(self, key):
        """Gets a claim from the payload. If claim does not exist, returns None"""
        return self.data.get(key, None)

    def to_json(self) -> bytes:
        """Converts the payload to a JSON formatted byte string."""
        return json.dumps(self.data, separators=(",", ":")).encode("utf8")

    @classmethod
    def from_json(cls, json_string: str) -> "Payload":
        """Creates a Payload object from a JSON string."""
        payload_data = json.loads(json_string)
        logging.debug(f"Decoded Payload from JSON: {payload_data}")
        return cls(payload_data)

    def encode(self) -> str:
        """Returns a base64url-encoded string with padding removed."""
        return base64.urlsafe_b64encode(self.to_json()).decode().strip('=')

    def diff_claims(self, other: "Payload") -> dict[str, list[str]]:
        """
        Compares the custom claims of two Payload instances and returns the missing or added claims.

        Args:
            other (Payload): Another instance of Payload for comparison.

        Returns:
            dict[str, list[str]]: A dictionary containing missing or added claims.

        Examples:
            header1 = JWTHeader(alg="HS256", custom_claims={"sub": "123", "aud": "example"})
            header2 = JWTHeader(alg="HS256", custom_claims={"sub": "123", "iss": "issuer"})

            claim_diff = header1.diff_claims(header2)
            print(claim_diff)
        """
        self_claims = set(self.data.keys())
        other_claims = set(other.data.keys())

        missing_claims = self_claims - other_claims
        added_claims = other_claims - self_claims

        diff_result = {"missing_claims": list(missing_claims), "added_claims": list(added_claims)}
        logging.debug(f"Difference in custom claims: {diff_result}")

        return diff_result

    def validate_claims(self) -> dict[str, list[str]]:
        """
        Validates JWT claims such as "exp" (expiration time), "iat" (issued at), and "nbf" (not before).

        Returns:
            dict[str, list[str]]: True if all claims are valid, False otherwise.
        """
        current_time = datetime.utcnow().replace(tzinfo=timezone.utc)
        problems = {}

        # Validate "exp" (expiration time)
        exp_claim = self.data.get("exp")
        if exp_claim is not None and isinstance(exp_claim, int):
            exp_time = datetime.utcfromtimestamp(exp_claim).replace(tzinfo=timezone.utc)
            if not exp_claim:
                problems["exp"] = ["JWT missing 'exp'."]
            elif current_time > exp_time:
                problems["exp"] = ["JWT has expired."]

        # Validate "iat" (issued at)
        iat_claim = self.data.get("iat")
        if iat_claim is not None and isinstance(iat_claim, int):
            iat_time = datetime.utcfromtimestamp(iat_claim).replace(tzinfo=timezone.utc)
            if not iat_time:
                problems["iat"] = ["JWT missing 'iat'."]
            elif current_time < iat_time:
                problems["iat"] = ["JWT issued in the future."]

        # Validate "nbf" (not before)
        nbf_claim = self.data.get("nbf")
        if nbf_claim is not None and isinstance(nbf_claim, int):
            nbf_time = datetime.utcfromtimestamp(nbf_claim).replace(tzinfo=timezone.utc)
            if not nbf_claim:
                problems["nbf"] = ["JWT missing 'nbf'."]
            elif current_time < nbf_time:
                problems["nbf"] = ["JWT not valid yet."]

        logging.debug(f"Validation results for claims: {problems}")
        return problems

    def get_provided_payload(self):
        """Returns the value of the private provided_payload attribute."""
        return self._provided_payload

    def set_provided_payload(self, value):
        """Sets the value of the private provided_payload attribute."""
        self._provided_payload = value
        logging.debug(f"Set provided payload: {value}")

    provided_payload = property(get_provided_payload, set_provided_payload)

    def __str__(self) -> str:
        """String representation of the payload."""
        return f"Payload(data={self.data})"

    def __repr__(self) -> str:
        """Official string representation of the payload."""
        return f"Payload(data={self.data})"

    def __eq__(self, other: "Payload") -> bool:
        """Equality comparison between two payloads."""
        return self.data == other.data


class SigningConfig:
    """
    A JSON Web Token (JWT) Signature Configuration representation.

    Attributes:
        key (bytes): The key used for signing.

    Methods:
        generate_hmac_signature: Generates HMAC signature for HMAC-based algorithms.
        generate_rsa_signature: Generates RSA signature for RSA-based algorithms.

    Example:
        signingConfig = SigningConfig(key="secret_key", algorithm="HS256")
        jwt = (payload, header, signingConfig)
        signature = jwt.sign()
    """

    def __init__(self, key: Union[str, None], algorithm: str):
        self.key = key
        self.algorithm = algorithm
        logging.debug(f"Initialized SigningConfig with key={key}, algorithm={algorithm}")

    def to_json(self) -> bytes:
        """Converts the header to a JSON byte string."""
        signing_dict = {
            "key": self.key,
            "alg": self.algorithm,
        }
        return json.dumps(signing_dict, separators=(",", ":")).encode("utf8")

    def __str__(self) -> str:
        """String representation of the Signature."""
        return f"Signature(key={self.key}, algorithm={self.algorithm})"


class JWT:
    """
    JSON Web Token (JWT) representation.

    Attributes:
        header (Header): The token header.
        payload (Payload): The token payload.
        signing_config (SigningConfig): The token signature.

    Methods:
        sign: Generates the signature for the given data.
        verify: Verifies the integrity of a JWT.
        from_jwt_string: Creates a JWT object from a JWT string.
        encode: Generates the complete JWT by encoding header, payload, and signature.

    Dunder Methods:
        __str__: String representation of the JWT.
        __repr__: Official string representation of the JWT.
        __eq__: Equality comparison between two JWTs.

    Example:
        jwt = JWT(header=Header(alg="HS256", typ="JWT"),
                  payload=Payload(data={"user_id": 123, "username": "john_doe"}),
                  signing_config=SigningConfig(key="secret_key", algorithm="HS256"))
        encoded_token = jwt.encode()
        is_valid = jwt.verify(encoded_token)
    """

    def __init__(self, header: Header, payload: Payload, signing_config: Optional[SigningConfig] = None, jwks: Optional[JWKS] = None):
        self.header = header
        self.payload = payload
        self.signing_config = signing_config
        self.jwks = jwks
        self._provided_signature = None
        logging.debug(f"Initialized JWT with header={header}, payload={payload}, signing_config={signing_config}")

    def sign(self) -> str:
        """Generates the signature for the given header and payload."""
        data = f"{self.header.encode()}.{self.payload.encode()}"

        if self.signing_config.algorithm.startswith("HS"):
            digest = (hmac.new(self.signing_config.key.encode("utf8"), data.encode("utf8"), "sha256")).digest()
            self._provided_signature = base64.urlsafe_b64encode(digest).decode().strip('=')
            logging.debug(f"Generated HMAC signature: {self._provided_signature}")
            return self._provided_signature

    def encode(self):
        """String representation of the JWT."""
        jwt_str = ""

        if self.header:
            jwt_str += f"{self.header.encode()}."
        else:
            logging.warning("Invalid JWT: Missing header.")

        if self.payload:
            jwt_str += f"{self.payload.encode()}."
        else:
            logging.warning("Invalid JWT: Missing payload.")

        if self.signing_config:
            jwt_str += f"{self._provided_signature}"
        else:
            logging.warning("JWT signature not configured.")

        logging.debug(f"Encoded JWT: {jwt_str}")
        return jwt_str

    @classmethod
    def from_jwt_string(cls, jwt_string: str) -> Union["JWT", None]:
        """
        Creates a JWT object from a JWT string.

        Args:
            jwt_string (str): The JWT string to parse.

        Returns:
            JWT: The created JWT object.
        """
        parts = jwt_string.split(".")

        if len(parts) < 2:
            logging.critical(f"Unable to decode JWT: '{jwt_string}'.\nInsufficient parts, expected at least 2. Got {len(parts)}.")
            return None

        header_json = base64.urlsafe_b64decode(parts[0] + "==").decode("utf8")
        payload_json = base64.urlsafe_b64decode(parts[1] + "==").decode("utf8")

        try:
            header = Header.from_json(header_json)
            logging.debug(f"Decoded JWT header: {header_json}")
        except json.decoder.JSONDecodeError as error:
            logging.critical(f"Unable to decode JWT header: '{jwt_string}'.\nExpecting: JSON value. Got: {header_json}")
            logging.debug(f"The following error was returned by `json.decoder.JSONDecodeError`:\n{error.msg}")
            return None
        else:
            header.set_provided_header(parts[0])

        try:
            payload = Payload.from_json(payload_json)
            logging.debug(f"Decoded JWT payload: {payload_json}")
        except json.decoder.JSONDecodeError as error:
            logging.critical(f"Unable to decode JWT payload: '{jwt_string}'.\nExpecting: JSON value. Got: {header_json}")
            logging.debug(f"The following error was returned by `json.decoder.JSONDecodeError`:\n{error.msg}")
            return None
        else:
            payload.set_provided_payload(parts[1])

        jwt = cls(header, payload)

        if len(parts) == 3:
            jwt.set_provided_signature(parts[2])
            logging.debug(f"Set provided JWT signature: {parts[2]}")

            if header.alg:
                jwt.signing_config = SigningConfig(key=None, algorithm=header.alg)
                logging.debug(f"Initialized SigningConfig for JWT with alg={header.alg}")

        return jwt

    def get_key_from_jwks(self) -> Union[JWK, None]:
        """Retrieves the key from the JWKS based on the Key ID (kid)."""
        key = self.jwks.get_key_by_kid(self.signing_config.kid)
        logging.debug(f"Retrieved key from JWKS for kid={self.signing_config.kid}: {key}")
        return key

    def get_provided_signature(self):
        """Returns the value of the private provided_signature attribute."""
        return self._provided_signature

    def set_provided_signature(self, value):
        """Sets the value of the private provided_signature attribute."""
        self._provided_signature = value
        logging.debug(f"Set provided signature: {value}")

    provided_signature = property(get_provided_signature, set_provided_signature)

    def __str__(self) -> str:
        """String representation of the JWT."""
        return f"JWT(header={self.header}, payload={self.payload}, signature={self.get_provided_signature()}, signingConfig={self.signing_config})"

    def __repr__(self) -> str:
        """Official string representation of the JWT."""
        return f"JWT(header={repr(self.header)}, payload={repr(self.payload)}, signature={repr(self.get_provided_signature())}, signingConfig={self.signing_config})"

    def __eq__(self, other: "JWT") -> bool:
        """Equality comparison between two JWTs."""
        return (
                self.header == other.header
                and self.payload == other.payload
                and self.signing_config == other.signing_config
        )
