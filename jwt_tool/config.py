import pathlib
from typing import Optional, Annotated, List
import pydantic
import toml

from Cryptodome.PublicKey import RSA, ECC

from jwt_tool import CONFIG_PATH

Url = Annotated[str, pydantic.PlainValidator(lambda value: str(pydantic.TypeAdapter(pydantic.AnyUrl).validate_python(value)))]
Path = Annotated[str, pydantic.PlainValidator(lambda value: str(pydantic.TypeAdapter(pathlib.Path).validate_python(value))), pydantic.PlainSerializer(lambda value: str(value))]


class General(pydantic.BaseModel):
    """
    General configuration settings.

    Attributes:
        version (str): Version number of the configuration.
        user_agent (str): The user agent string to use for requests.
        proxy_host (Optional[pydantic.IPvAnyNetwork]): The proxy host address.
        proxy_port (Optional[int]): The proxy port number.
        jwks_kid (str): The Key ID for JWKS.
        follow_redirects (bool): Whether to follow redirects.
    """
    version: str = "1.0.0"
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) jwt_tool"
    proxy_host: Optional[pydantic.IPvAnyNetwork] = "127.0.0.1"
    proxy_port: Optional[int] = 8080
    jwks_kid: str = "jwt_tool"
    follow_redirects: bool = False


class JWSCrypto(pydantic.BaseModel):
    """
    Cryptographic configuration settings.

    Attributes:
        rsa_public_key (Path): Path to the RSA public key.
        rsa_private_key (Path): Path to the RSA private key.
        ecc_public_key (Path): Path to the ECC public key.
        ecc_private_key (Path): Path to the ECC private key.
        jwks_name (Path): Path to the JWKS file.
        rsa_key_size (int): Size of the RSA key.
        rsa_exponent_size (int): Exponent size for the RSA key.
        rsa_export_format (str): Export format for the RSA key.
        ecc_curve (str): ECC curve to use.
        ecc_export_format (str): Export format for the ECC key.
    """
    rsa_public_key: Path = CONFIG_PATH / "default_RSA_public_key"
    rsa_private_key: Path = CONFIG_PATH / "default_RSA_private_key.pem"
    ecc_public_key: Path = CONFIG_PATH / "default_EC_public_key"
    ecc_private_key: Path = CONFIG_PATH / "default_EC_private_key.pem"
    jwks_name: Path = CONFIG_PATH / "default_custom_jwks.json"

    rsa_key_size: int = 2048
    rsa_exponent_size: int = 65537
    rsa_export_format: str = "PEM"

    ecc_curve: str = "P-256"
    ecc_export_format: str = "PEM"

    def generate_rsa_key(self):
        """
        Generates an RSA key pair and saves it to the specified paths.
        """
        rsa_key = RSA.generate(self.rsa_key_size, e=self.rsa_exponent_size)
        public = rsa_key.public_key().export_key(format=self.rsa_export_format)
        private = rsa_key.export_key(format=self.rsa_export_format)

        try:
            with pathlib.Path(self.rsa_public_key).open(mode="xb") as file:
                file.write(public)
        except FileExistsError:
            pass

        try:
            with pathlib.Path(self.rsa_private_key).open(mode="xb") as file:
                file.write(private)
        except FileExistsError:
            pass

    def generate_ecc_key(self):
        """
        Generates an ECC key pair and saves it to the specified paths.
        """
        ecc_key = ECC.generate(curve=self.ecc_curve)
        public = ecc_key.public_key().export_key(format=self.ecc_export_format)
        private = ecc_key.export_key(format=self.ecc_export_format)

        try:
            with pathlib.Path(self.ecc_public_key).open(mode="x") as file:
                file.write(public)
        except FileExistsError:
            pass

        try:
            with pathlib.Path(self.ecc_private_key).open(mode="x") as file:
                file.write(private)
        except FileExistsError:
            pass


class Input(pydantic.BaseModel):
    """
    Input configuration settings.

    Attributes:
        wordlist (Path): Path to the wordlist file.
        common_headers (Path): Path to the common headers file.
        common_payloads (Path): Path to the common payloads file.
    """
    wordlist: Path = "jwt-common.txt"
    common_headers: Path = "common-headers.txt"
    common_payloads: Path = "common-payloads.txt"


class JWKS(pydantic.BaseModel):
    """
    JWKS (JSON Web Key Set) configuration settings.

    Attributes:
        jwks_location (Url): URL where the custom JWKS file is hosted.
        jwks_dynamic (Url): URL for dynamic JWKS.
        http_listener (Url): URL for an HTTP listener to see host interaction.
    """
    jwks_location: Optional[Url] = "https://example.com/jwks"
    jwks_dynamic: Optional[Url] = "https://example.com/jwks"
    http_listener: Optional[Url] = "https://example.com/jwks"


class Target(pydantic.BaseModel):
    """
    Target configuration settings.

    Attributes:
        site_url (Url): The URL of the target site.
        http_version (Optional[str]): The HTTP version to use ("http1", "http2", or "auto").
        port (Optional[int]): The port number if it's not 443 or 80.
        http_methods (Optional[List[str]]): List of HTTP methods to use.
        jwt_location (Optional[str]): Where the JWT should be set ("header", "body", or "url").
        jwt_header (Optional[str]): The header that the JWT should be attached to.
        jwt_param (Optional[str]): The request parameter or URL parameter that the JWT should be attached to.
    """
    site_url: Url = "https://example.com"
    http_version: Optional[str] = "auto"
    port: Optional[int] = None
    http_methods: Optional[List[str]] = ["GET", "POST"]
    jwt_location: Optional[str] = "header"
    jwt_header: Optional[str] = "Authorization"
    jwt_param: Optional[str] = "token"


class Config(pydantic.BaseModel):
    """
    Main configuration class that includes general, cryptographic, input, JWKS, and target settings.

    Attributes:
        general (General): General configuration settings.
        crypto (JWSCrypto): Cryptographic configuration settings.
        input (Input): Input configuration settings.
        jwks (JWKS): JWKS configuration settings.
        target (Target): Target configuration settings.
    """
    general: General = General()
    crypto: JWSCrypto = JWSCrypto()
    input: Input = Input()
    jwks: JWKS = JWKS()
    target: Target = Target()

    def save_to_file(self):
        """
        Saves the configuration to a file.
        """
        CONFIG_PATH.mkdir(parents=True, exist_ok=True)
        with (CONFIG_PATH / "config.conf").open(mode="w") as file:
            pydantic_model = self.model_dump(mode='python')
            toml.dump(pydantic_model, file)

    @classmethod
    def load_from_file(cls):
        """
        Loads the configuration from a file.

        Returns:
            Config: The loaded configuration instance.
        """
        with (CONFIG_PATH / "config.conf").open(mode="r") as file:
            config_data = toml.load(file)
        return cls(**config_data)
