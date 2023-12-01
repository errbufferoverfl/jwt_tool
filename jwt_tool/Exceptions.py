class JWTValidationError(Exception):
    """Custom exception for JWT validation errors."""

    def __init__(self, message="JWT validation failed"):
        self.message = message
        super().__init__(self.message)
