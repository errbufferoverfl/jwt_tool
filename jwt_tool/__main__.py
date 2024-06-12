import json
import logging
from pprint import pprint
from typing import Union

import click
from pydantic import ValidationError
from termcolor import colored
from urlstd.parse import URL

from jwt_tool import CONFIG_PATH
from jwt_tool.HTTPClient import HttpClient
from jwt_tool.JWT import JWT
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
    loaded_config: Union[Config, None] = None

    try:
        # Attempt to load the configuration from file.
        loaded_config = Config.load_from_file()
    except FileNotFoundError:
        # Log a warning if the configuration file does not exist and create a new one with default values.
        logger.warning(
            f"Config file not found in {CONFIG_PATH}. Creating new config template."
        )
        loaded_config = Config()
        loaded_config.save_to_file()
        # Attempt to reload the configuration from the newly created file.
        loaded_config = Config.load_from_file()

    try:
        # Validate the loaded configuration model.
        loaded_config = Config.model_validate(loaded_config)
    except ValidationError as e:
        logger.warning(e)
    else:
        return loaded_config


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
    logger_instance = logging.getLogger()

    # Set the overall log level
    logger_instance.setLevel(logging.getLevelName(logging.INFO))

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
    logger_instance.addHandler(console_handler)
    logger_instance.addHandler(file_handler)


@click.group()
@click.pass_context
def cli(ctx):
    """If you don't have a token, try this one:

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0ODUxNDA5ODQsImlhdCI6MTQ4NTEzNzM4NCwiaXNzIjoiZXhhbXBsZS5jb20iLCJzdWIiOiIyOWFjMGMxOC0wYjRhLTQyY2YtODJmYy0wM2Q1NzAzMThhMWQiLCJhcHBsaWNhdGlvbklkIjoiNzkxMDM3MzQtOTdhYi00ZDFhLWFmMzctZTAwNmQwNWQyOTUyIiwicm9sZXMiOltdfQ.Mp0Pcwsz5VECK11Kf2ZZNF_SMKu5CgBeLN9ZOP04kZo"""
    ctx.ensure_object(dict)
    ctx.obj['user_config'] = _init_config()


@cli.command(help=r"""Decodes a JSON Web Token (JWT) and displays its header, payload, and signature.

Takes a JWT string and decodes it, providing a human-readable format of its contents. 
The decoded JWT includes the header, payload, and provided signature.

Usage examples:

1. Decode a JWT and display the components:
   $ jwt_tool decode <JWT_STRING>

2. Decode a JWT provided in a file:
   $ jwt_tool decode -f jwt.txt

Options:
    jwt    The JWT string to decode.
    -f, --file    Optional path to a file containing the JWT string.
""")
@click.argument("jwt", type=click.STRING, required=False)
@click.option('-f', '--file', type=click.File('r'), help="Optional path to a file containing the JWT string.")
def decode(jwt, file):
    """
    Decodes a JSON Web Token (JWT) and displays its header, payload, and signature.

    This function takes a JWT string or a file containing a JWT string, decodes it, and
    prints the header, payload, and signature in a human-readable format.
    """
    if file:
        jwt = file.read().strip()
    if not jwt:
        click.echo("Error: No JWT provided. Please provide a JWT string or use the --file option.")
        return

    try:
        jwt_object = JWT.from_jwt_string(jwt)
    except Exception as e:
        click.echo(f"Error decoding JWT: {e}")
        return

    print(colored("Token:", attrs=["bold"]))
    print(f"{colored(jwt_object.header.get_provided_header(), "green")}.{colored(jwt_object.payload.get_provided_payload(), "blue")}.{colored(jwt_object.get_provided_signature(), "red")}")
    print()
    print(colored("Header:", attrs=["bold"]))
    print(jwt_object.header.to_json().decode("utf8"))
    print(colored("Payload:", attrs=["bold"]))
    print(jwt_object.payload.to_json().decode("utf8"))
    print(colored("Signature:", attrs=["bold"]))
    print(jwt_object.signing_config.to_json().decode("utf8"))


@cli.command(help=r"")
@click.argument("jwt", type=click.STRING)
@click.option('-u', '--url', help="The URL to test the JWT against.")
@click.pass_context
def scan(ctx, jwt, url):
    user_config = ctx.obj['user_config']
    target_url = url

    # Check if both URL from CLI and URL from config are set
    if url and user_config.target.site_url:
        # Prompt the user to pick between the config file URL or the CLI URL
        choice = click.prompt(
            "Both a URL from the config file and a URL from the CLI parameter are set. "
            "Which one would you like to use? (config/cli)",
            type=click.Choice(['config', 'cli']),
            default='cli'
        )
        if choice == 'config':
            target_url = user_config.target.site_url
        else:
            target_url = url
    elif not url:
        # Use URL from config if CLI URL is not set
        target_url = user_config.target.site_url

    if target_url:
        target_url = URL(target_url)
        logging.info(f"Target: {target_url}")

    if jwt:
        jwt_object = JWT.from_jwt_string(jwt)

    target_config = user_config.target

    http_client = HttpClient(url, http_version=target_config.http_version)


# Call the _init_logging function to set up the logger
_init_logging()

# Now you can use the logger throughout your module
logger = logging.getLogger(__name__)

if __name__ == "__main__":
    cli()
