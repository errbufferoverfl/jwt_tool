import httpx


class HTTPClient:
    def __init__(self):
        self.client = httpx.Client

    def close(self):
        self.client.close()
