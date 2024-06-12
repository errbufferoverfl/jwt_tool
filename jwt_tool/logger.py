"""
Logging classes are configured using the pattern set out by the Python3 docs.
See more: https://docs.python.org/3/howto/logging.html#configuring-logging
"""
import logging
import pathlib
from datetime import datetime
from typing import Annotated

import pydantic
import toml

from jwt_tool import CONFIG_PATH

# Define a dictionary mapping log levels to emojis
LOG_LEVEL_EMOJIS = {
    "DEBUG": "🐛",
    "INFO": "ℹ️",
    "WARNING": "⚠️",
    "ERROR": "❌",
    "CRITICAL": "🔥",
    "OUTPUT": "📤"  # Custom emoji for OUTPUT level
}

# Define the new log level and its numeric value
OUTPUT_LEVEL_NUM = 25
logging.addLevelName(OUTPUT_LEVEL_NUM, "OUTPUT")


def output(self, message, *args, **kws):
    if self.isEnabledFor(OUTPUT_LEVEL_NUM):
        self._log(OUTPUT_LEVEL_NUM, message, args, **kws)


logging.Logger.output = output

Url = Annotated[str, pydantic.BeforeValidator(lambda value: str(pydantic.TypeAdapter(pydantic.AnyUrl).validate_python(value)))]
Path = Annotated[str, pydantic.BeforeValidator(lambda value: str(pydantic.TypeAdapter(pathlib.Path).validate_python(value)))]


class ConsoleLoggerSettings(pydantic.BaseModel):
    level: str = "INFO"
    format: str = "%(emoji_levelname)s %(message)s"


# Create a custom formatter class
class EmojiLogFormatter(logging.Formatter):
    def format(self, record):
        # Replace the level name with the corresponding emoji
        record.emoji_levelname = LOG_LEVEL_EMOJIS.get(record.levelname, record.levelname)
        return super().format(record)


# Create a custom formatter class for file and syslog
class DefaultLogFormatter(logging.Formatter):
    pass


class FileLoggerSettings(pydantic.BaseModel):
    level: str = "INFO"
    format: str = "%(asctime)s - %(levelname)s - %(message)s"
    filename: Path = None

    def __init__(self, **data):
        super().__init__(**data)
        # Determine the root directory of the project
        root_dir = pathlib.Path(__file__).resolve().parent.parent
        # Create logs directory if it doesn't exist
        log_dir = root_dir / 'logs'
        log_dir.mkdir(parents=True, exist_ok=True)
        # Generate a unique log file name with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.filename = log_dir / f"app_{timestamp}.log"


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


def init_logging():
    """
    Initialize the logging configuration.

    Attempts to load the logging configuration from a file. If the file is not
    found, default values are used, and the configuration is saved to a file.

    Raises:
        FileNotFoundError: If the logging configuration file is not found during loading.
    """
    try:
        logger_config = LoggerConfig.load_from_file()
    except FileNotFoundError:
        logger_config = LoggerConfig()
        logger_config.save_to_file()
        logging.warning("Logger configuration file not found. Using default configuration and saving it.")

    # Create a logger with the given name (root logger in this case)
    logger_instance = logging.getLogger()

    # Set the overall log level
    logger_instance.setLevel(logging.getLevelName(logging.INFO))

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.getLevelName(logger_config.console.level))
    console_formatter = EmojiLogFormatter(logger_config.console.format)
    console_handler.setFormatter(console_formatter)
    logger_instance.addHandler(console_handler)

    # File handler
    file_handler = logging.FileHandler(logger_config.file.filename)
    file_handler.setLevel(logging.getLevelName(logger_config.file.level))
    file_formatter = DefaultLogFormatter(logger_config.file.format)
    file_handler.setFormatter(file_formatter)
    logger_instance.addHandler(file_handler)

    # Syslog handler
    # syslog_handler = logging.handlers.SysLogHandler(address=logger_config.syslog.address)
    # syslog_handler.setLevel(logging.getLevelName(logger_config.syslog.level))
    # syslog_formatter = DefaultLogFormatter(logger_config.syslog.format)
    # syslog_handler.setFormatter(syslog_formatter)
    # logger_instance.addHandler(syslog_handler)

    return logger_instance
