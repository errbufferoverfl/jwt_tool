import pathlib
from typing import Optional, Annotated, Any

import pydantic
import toml
from Cryptodome.PublicKey import RSA, ECC

from jwt_tool import CONFIG_PATH


Url = Annotated[str, pydantic.PlainValidator(lambda value: str(pydantic.TypeAdapter(pydantic.AnyUrl).validate_python(value)))]
Path = Annotated[str, pydantic.PlainValidator(lambda value: str(pydantic.TypeAdapter(pathlib.Path).validate_python(value))), pydantic.PlainSerializer(lambda value: str(value))]


class General(pydantic.BaseModel):
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) jwt_tool"
    # Docker installation set proxy_host to "host.docker.internal:8080"
    proxy_host: Optional[pydantic.IPvAnyNetwork] = "127.0.0.1"
    proxy_port: Optional[int] = 8080
    jwks_kid: str = "jwt_tool"
    follow_redirects: bool = False


class Crypto(pydantic.BaseModel):
    rsa_public_key: Path = CONFIG_PATH / "default_RSA_public_key.pem"
    rsa_private_key: Path = CONFIG_PATH / "default_RSA_private_key.pem"
    ecc_public_key: Path = CONFIG_PATH / "default_EC_public_key.pem"
    ecc_private_key: Path = CONFIG_PATH / "default_EC_private_key.pem"
    jwks_name: Path = CONFIG_PATH / "default_custom_jwks.json"

    rsa_key_size: int = 2048
    rsa_exponent_size: int = 65537
    rsa_export_format: str = "PEM"

    ecc_curve: str = "P-256"
    ecc_export_format: str = "PEM"

    def generate_rsa_key(self):
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
        ecc_key = ECC.generate(curve=self.ecc_curve)
        public = ecc_key.public_key().export_key(format=self.ecc_export_format)
        private = ecc_key.export_key(format=self.ecc_export_format)

        try:
            with pathlib.Path(self.ecc_public_key).open(mode="xb") as file:
                file.write(public)
        except FileExistsError:
            pass

        try:
            with pathlib.Path(self.ecc_private_key).open(mode="xb") as file:
                file.write(private)
        except FileExistsError:
            pass



class Input(pydantic.BaseModel):
    wordlist: Path = "jwt-common.txt"
    common_headers: Path = "common-headers.txt"
    common_payloads: Path = "common-payloads.txt"


class JWKS(pydantic.BaseModel):
    # Set this to the URL you are hosting your custom JWKS file
    jwks_location: Optional[Url] = None
    jwks_dynamic: Optional[Url] = None
    # Set this to a Burp Collaborator server, or some other place to see host interaction
    http_listener: Optional[Url] = None


class Config(pydantic.BaseModel):
    general: General = General()
    crypto: Crypto = Crypto()
    input: Input = Input()
    jwks: JWKS = JWKS()

    def save_to_file(self):
        with (CONFIG_PATH / "config.conf").open(mode="x") as file:
            pydantic_model = self.model_dump(mode='python')
            toml.dump(pydantic_model, file)

    @classmethod
    def load_from_file(cls):
        with (CONFIG_PATH / "config.conf").open(mode="r") as file:
            config_data = toml.load(file)
        return cls(**config_data)
