from typing import List, Union

from jwt_tool.JWK import JWK


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
