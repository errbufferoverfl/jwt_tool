from typing import List

import httpx


class HttpClient:
    """
    A simple HTTP client that supports HTTP/1.1, HTTP/2, or auto-configuration based on server capabilities.

    Attributes:
        base_url (str): The base URL for the API.
        client (httpx.Client): The httpx client used for making requests.
    """

    def __init__(self, base_url: str, http_version: str = "auto"):
        """
        Initializes the HttpClient with the specified base URL and HTTP version.

        Args:
            base_url (str): The base URL for the API.
            http_version (str): The HTTP version to use ("http1", "http2", or "auto").

        Raises:
            ValueError: If an invalid HTTP version is specified.
        """
        self.base_url = base_url
        self.client = self._create_client(http_version)

    def _create_client(self, http_version: str) -> httpx.Client:
        """
        Creates an httpx client based on the specified HTTP version.

        Args:
            http_version (str): The HTTP version to use ("http1", "http2", or "auto").

        Returns:
            httpx.Client: The configured httpx client.

        Raises:
            ValueError: If an invalid HTTP version is specified.
        """
        if http_version == "http2":
            return httpx.Client(http2=True)
        elif http_version == "http1":
            return httpx.Client(http2=False)
        elif http_version == "auto":
            return httpx.Client(http2=True, http1=True)
        else:
            raise ValueError("Invalid HTTP version specified. Choose 'http1', 'http2', or 'auto'.")

    def get(self, endpoint: str, params: dict = None) -> dict:
        """
        Sends a GET request to the specified endpoint.

        Args:
            endpoint (str): The API endpoint to send the GET request to.
            params (dict, optional): Query parameters to include in the request.

        Returns:
            dict: The JSON response from the server.
        """
        url = f"{self.base_url}{endpoint}"
        response = self.client.get(url, params=params)
        return self._handle_response(response)

    def post(self, endpoint: str, data: dict = None, json: dict = None) -> dict:
        """
        Sends a POST request to the specified endpoint.

        Args:
            endpoint (str): The API endpoint to send the POST request to.
            data (dict, optional): Form data to include in the request.
            json (dict, optional): JSON data to include in the request.

        Returns:
            dict: The JSON response from the server.
        """
        url = f"{self.base_url}{endpoint}"
        response = self.client.post(url, data=data, json=json)
        return self._handle_response(response)

    def put(self, endpoint: str, data: dict = None, json: dict = None) -> dict:
        """
        Sends a PUT request to the specified endpoint.

        Args:
            endpoint (str): The API endpoint to send the PUT request to.
            data (dict, optional): Form data to include in the request.
            json (dict, optional): JSON data to include in the request.

        Returns:
            dict: The JSON response from the server.
        """
        url = f"{self.base_url}{endpoint}"
        response = self.client.put(url, data=data, json=json)
        return self._handle_response(response)

    def delete(self, endpoint: str, params: dict = None) -> dict:
        """
        Sends a DELETE request to the specified endpoint.

        Args:
            endpoint (str): The API endpoint to send the DELETE request to.
            params (dict, optional): Query parameters to include in the request.

        Returns:
            dict: The JSON response from the server.
        """
        url = f"{self.base_url}{endpoint}"
        response = self.client.delete(url, params=params)
        return self._handle_response(response)

    def _handle_response(self, response: httpx.Response) -> dict:
        """
        Handles the response from the server.

        Args:
            response (httpx.Response): The response object.

        Returns:
            dict: The JSON response from the server.

        Raises:
            httpx.HTTPStatusError: If the response status code indicates an error.
            httpx.RequestError: If there is an error while making the request.
        """
        try:
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            print(f"HTTP error occurred: {e.response.status_code} - {e.response.text}")
            return None
        except httpx.RequestError as e:
            print(f"Request error occurred: {e}")
            return None


class HttpMethodFactory:
    """
    HTTP method factory that uses the specified HTTP methods from the Target configuration to make requests using the HttpClient.

    Attributes:
        client (HttpClient): The HTTP client to use for making requests.
        methods (List[str]): List of HTTP methods to use.
    """

    def __init__(self, client: HttpClient, methods: List[str]):
        """
        Initializes the HttpMethodFactory with the specified HTTP client and methods.

        Args:
            client (HttpClient): The HTTP client to use for making requests.
            methods (List[str]): List of HTTP methods to use.
        """
        self.client = client
        self.methods = methods

    def make_request(self, endpoint: str, data: dict = None, json: dict = None, params: dict = None):
        """
        Makes a request to the specified endpoint using the configured HTTP methods.

        Args:
            endpoint (str): The API endpoint to send the request to.
            data (dict, optional): Form data to include in the request (for POST/PUT).
            json (dict, optional): JSON data to include in the request (for POST/PUT).
            params (dict, optional): Query parameters to include in the request (for GET/DELETE).

        Returns:
            dict: The JSON response from the server.
        """
        responses = {}
        for method in self.methods:
            if method.upper() == "GET":
                responses['GET'] = self.client.get(endpoint, params=params)
            elif method.upper() == "POST":
                responses['POST'] = self.client.post(endpoint, data=data, json=json)
            elif method.upper() == "PUT":
                responses['PUT'] = self.client.put(endpoint, data=data, json=json)
            elif method.upper() == "DELETE":
                responses['DELETE'] = self.client.delete(endpoint, params=params)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
        return responses