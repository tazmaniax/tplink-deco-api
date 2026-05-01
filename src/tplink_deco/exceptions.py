class DecoError(Exception):
    pass


class AuthenticationError(DecoError):
    pass


class CryptoError(DecoError):
    pass


class TransportError(DecoError):
    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


class ApiError(DecoError):
    def __init__(self, error_code: int):
        super().__init__(f"API returned error_code={error_code}")
        self.error_code = error_code
