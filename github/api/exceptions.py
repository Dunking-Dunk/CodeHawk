class AsyncTimeoutError(Exception):
    """Raised when async functions run more than the timeout period
    Use with async_timeout decorator to signal that the wrapped asynchronous function
    has exceeded the specified time limit for execution
    """