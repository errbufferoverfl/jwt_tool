"""
Logging classes are configured using the pattern set out by the Python3 docs.
See more: https://docs.python.org/3/howto/logging.html#configuring-logging
"""
import pathlib
from typing import Annotated

import pydantic
import toml

from jwt_tool import CONFIG_PATH

Url = Annotated[str, pydantic.BeforeValidator(lambda value: str(pydantic.TypeAdapter(pydantic.AnyUrl).validate_python(value)))]
Path = Annotated[str, pydantic.BeforeValidator(lambda value: str(pydantic.TypeAdapter(pathlib.Path).validate_python(value)))]


class ConsoleLoggerSettings(pydantic.BaseModel):
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"


class FileLoggerSettings(pydantic.BaseModel):
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    filename: Path = "app.log"


class SyslogLoggerSettings(pydantic.BaseModel):
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    # Using AnyUrl to allow either a string or a URL
    address: Url = "udp://localhost:514"


class LoggerConfig(pydantic.BaseModel):
    version: pydantic.PositiveInt = 1

    console: ConsoleLoggerSettings = ConsoleLoggerSettings()
    file: FileLoggerSettings = FileLoggerSettings()
    syslog: SyslogLoggerSettings = SyslogLoggerSettings()

    def save_to_file(self):
        with (CONFIG_PATH / "logger.conf").open(mode="x") as file:
            pydantic_model = self.model_dump(mode='python')
            toml.dump(pydantic_model, file)

    @classmethod
    def load_from_file(cls):
        with (CONFIG_PATH / "logger.conf").open(mode="r") as file:
            config_data = toml.load(file)
        return cls(**config_data)
