import click

from jwt_tool.HTTPClient import HTTPClient


class PlaybookCommonErrors:
    def __init__(self, http_client: HTTPClient, jwt: JWT):
        self.http_client = http_client
        self.jwt = jwt

    @main.command()
    def run(self):
        pass
