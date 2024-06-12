from jwt_tool.HTTPClient import HttpClient
from jwt_tool.JWT import JWT


class Playbook:
    def __init__(self, http_client: HttpClient, jwt: JWT):
        self.http_client = http_client
        self.jwt = jwt

    def run(self):
        pass
