class IntelError(Exception):
    pass


class IntelRateLimitError(IntelError):
    pass


class IntelAuthError(IntelError):
    pass


class IntelNetworkError(IntelError):
    pass
