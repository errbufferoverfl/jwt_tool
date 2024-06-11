import logging

import click
from urlstd.parse import URL

from jwt_tool.HTTPClient import HTTPClient
from jwt_tool.JWT import JWT
from jwt_tool.Playbook import Playbook
from jwt_tool.config import Config
from jwt_tool.logger import LoggerConfig

"""
This is where we expose all the functions to click.
"""


def _init_config():
    """
    Initialize the configuration settings.

    Creates a Config instance, attempts to load the configuration from a file,
    and generates cryptographic keys if necessary. If the configuration file
    is not found, default values are used, and the configuration is saved to a file.

    Raises:
        FileNotFoundError: If the configuration file is not found during loading.
    """
    config_conf: Config = Config()

    try:
        config_conf = Config.load_from_file()
    except FileNotFoundError:
        config_conf.save_to_file()

    config_conf.crypto.generate_rsa_key()
    config_conf.crypto.generate_ecc_key()


def _init_logging():
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

    # Create a logger with the given name (root logger in this case)
    logger = logging.getLogger()

    # Set the overall log level
    logger.setLevel(logging.getLevelName(logging.INFO))

    # Create a console handler and set its log level
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.getLevelName(logger_config.console.level))

    # Create a file handler and set its log level
    file_handler = logging.FileHandler(logger_config.file.filename)
    file_handler.setLevel(logging.getLevelName(logger_config.file.level))

    # Create a formatter and attach it to the handlers
    console_formatter = logging.Formatter(logger_config.console.format)
    file_formatter = logging.Formatter(logger_config.file.format)

    console_handler.setFormatter(console_formatter)
    file_handler.setFormatter(file_formatter)

    # Add the handlers to the logger
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)


@click.command(help=r"""If you don't have a token, try this one:

eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.bsSwqj2c2uI9n7-ajmi3ixVGhPUiY7jO9SUn9dm15Po""")
@click.argument("jwt", type=click.STRING)
@click.option('-u', '--url', help="The URL to test the JWT against.")
def main(jwt, url):
    if url:
        url = URL(url)
        logging.info(f"Target: {url}")

    if jwt:
        jwt_object = JWT.from_jwt_string(jwt)

    http_client = HTTPClient()


@click.group("Playbooks")
@click.pass_context
def playbook(ctx):
    pass


@playbook.command()
@click.pass_context
def common_errors(ctx):
    """Run common errors check."""
    pass


@playbook.command()
@click.pass_context
def fuzz_parameters(ctx):
    """Run fuzz parameters check."""
    pass


@playbook.command()
@click.pass_context
def all_tests(ctx):
    """Run all tests."""
    playbook = ctx.obj
    playbook.run_all_tests()


#_init_config()

# Call the _init_logging function to set up the logger
_init_logging()

# Now you can use the logger throughout your module
logger = logging.getLogger(__name__)

main()
