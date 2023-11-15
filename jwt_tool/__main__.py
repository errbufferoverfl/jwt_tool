from jwt_tool.config import Config
from jwt_tool.logger import LoggerConfig

"""
This is where we expose all the functions to click.
"""


def _init_config():
    config_conf: Config = Config()
    # Try to load the configuration from a file
    try:
        config_conf = Config.load_from_file()
    except FileNotFoundError:
        # Use default values if the file doesn't exist
        config_conf.save_to_file()

    config_conf.crypto.generate_rsa_key()


def _init_logging():
    # Try to load the configuration from a file
    try:
        logger_config = LoggerConfig.load_from_file()
    except FileNotFoundError:
        # Use default values if the file doesn't exist
        logger_config = LoggerConfig()
        logger_config.save_to_file()


_init_config()
_init_logging()
