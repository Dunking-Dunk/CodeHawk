from typing import Any
import json
from requests.exceptions import HTTPError
import requests

class GithubException(Exception):
    """Base exception for all GitHub API errors."""
    def __init__(
        self,
        status: int,
        data: Any = None,
        headers: dict[str, str] | None = None,
        message: str | None = None,
    ):
        super().__init__()
        self.__status = status
        self.__data = data
        self.__headers = headers
        self.__message = message
        self.args = (status, data, headers, message)

    @property
    def message(self) -> str | None:
        """
        The error message returned by the GitHub API.
        """
        return self.__message

    @property
    def status(self) -> int:
        """
        The status code returned by the GitHub API.
        """
        return self.__status

    @property
    def data(self) -> Any:
        """
        The (decoded) data returned by the GitHub API.
        """
        return self.__data

    @property
    def headers(self) -> dict[str, str] | None:
        """
        The headers returned by the GitHub API.
        """
        return self.__headers

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.__str__()})"

    def __str__(self) -> str:
        msg = f"{self.status} - {self.__class__.__name__}"
        if self.__message:
            msg += f": {self.__message}"
        if self.data is not None:
            msg += f"\n{json.dumps(self.data, indent=2)}"
        return msg


# Specific Exceptions
class BadRequestException(GithubException):
    """400 - Invalid request syntax or parameters."""

class UnauthorizedException(GithubException):
    """401 - Authentication required or failed."""

class ForbiddenException(GithubException):
    """403 - Insufficient permissions or access denied."""

class BadCredentialsException(ForbiddenException):
    """403 - Invalid authentication credentials."""

class RateLimitExceededException(ForbiddenException):
    """403 - Rate limit exceeded."""

class BadUserAgentException(ForbiddenException):
    """403 - Invalid or missing User-Agent header."""

class NotFoundException(GithubException):
    """404 - Resource not found."""

class UnacceptableFormatException(GithubException):
    """406 - Requested format not supported."""

class ResourceGoneException(GithubException):
    """410 - Resource permanently removed."""

class TooManyRequestsException(GithubException):
    """429 - Secondary rate limit exceeded."""

class ServerErrorException(GithubException):
    """500 - GitHub server error."""

class BadGatewayException(GithubException):
    """502 - GitHub gateway error."""

class ServiceUnavailableException(GithubException):
    """503 - GitHub service unavailable."""

class GatewayTimeoutException(GithubException):
    """504 - Gateway timeout."""

class UnknownObjectException(NotFoundException):
    """404 - Alias for NotFoundException."""

class TwoFactorException(GithubException):
    """Requires two-factor authentication."""

class IncompletableObject(GithubException):
    """Missing URL to complete request."""

class BadAttributeException(Exception):
    """Unexpected data format from API response."""
    def __init__(
        self,
        actualValue: Any,
        expectedType: type,
        transformationException: Exception | None,
    ):
        self.actual_value = actualValue
        self.expected_type = expectedType
        self.transformation_exception = transformationException
        super().__init__(f"Expected {expectedType}, got {type(actualValue)}")


def _handle_http_error(error: HTTPError, response: requests.Response) -> None:
    """
    Map HTTP errors to specific exceptions.

    Args:
        error (HTTPError): The HTTP error raised by the requests library.
        response (requests.Response): The response object from the failed request.

    Raises:
        Specific GitHub API exception based on the status code.
    """
    status = response.status_code
    data = response.json() if response.content else None
    headers = dict(response.headers)
    message = data.get("message", None) if isinstance(data, dict) else None

    exception_map = {
        400: BadRequestException,
        401: UnauthorizedException,
        403: ForbiddenException,
        404: NotFoundException,
        406: UnacceptableFormatException,
        410: ResourceGoneException,
        429: TooManyRequestsException,
        500: ServerErrorException,
        502: BadGatewayException,
        503: ServiceUnavailableException,
        504: GatewayTimeoutException,
    }

    exc_class = exception_map.get(status, GithubException)

    #handling cases of status code 403
    if status == 403:
        if "rate limit" in (message or "").lower():
            exc_class = RateLimitExceededException
        elif "user agent" in (message or "").lower():
            exc_class = BadUserAgentException
        elif "credentials" in (message or "").lower():
            exc_class = BadCredentialsException

    # handling authentication 
    if status == 401 and headers.get("X-GitHub-OTP", "").startswith("required"):
        exc_class = TwoFactorException

    raise exc_class(
        status=status,
        data=data,
        headers=headers,
        message=message
    )