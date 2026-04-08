from fastapi import HTTPException, status

class AppBaseException(HTTPException):
    """Base class for all app exceptions."""

    pass

class InternalServerErrorException(AppBaseException):
    def __init__(self, detail: str = "Internal server error"):
        super().__init__(status_code=status.HTTP_403_FORBIDDEN, detail=detail)

class ResourceNotFoundException(AppBaseException):
    def __init__(self, resource_name: str = "Resource"):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"{resource_name} not found"
        )

class ForbiddenException(AppBaseException):
    def __init__(self, detail: str = "Not authorized to perform this action"):
        super().__init__(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


class BadRequestException(AppBaseException):
    def __init__(self, detail: str = "Bad Request"):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)

###########################

class SessionNotFoundException(ResourceNotFoundException):
    def __init__(self, resource_name: str = "Session"):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"{resource_name} not found"
        )

class UserNotFoundException(ResourceNotFoundException):
    def __init__(self, resource_name: str = "User"):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"{resource_name} not found"
        )

##########################

class AdminForibiddenFromCreatingApiKeyException(ForbiddenException):
    def __init__(self, detail: str = "Not authorized to perform this action"):
        super().__init__(status_code=status.HTTP_403_FORBIDDEN, detail="Admin is forbidden from creating api keys")

class AdminNeededException(ForbiddenException):
    def __init__(self, detail: str = "Not authorized to perform this action"):
        super().__init__(status_code=status.HTTP_403_FORBIDDEN, detail="Only admin can perform this action")

class AdminOrOwnerNeededException(ForbiddenException):
    def __init__(self, detail: str = "Not authorized to perform this action"):
        super().__init__(status_code=status.HTTP_403_FORBIDDEN, detail="Only admin or owner can perform this action")


#########################

class InvalidCredentialsException(BadRequestException):
    def __init__(self, detail: str = "Bad Request"):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid credentials")

class Required2FACodeException(BadRequestException):
    def __init__(self, detail: str = "Bad Request"):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail="Required 2FA code")

class Invalid2FACodeException(BadRequestException):
    def __init__(self, detail: str = "Bad Request"):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid 2FA code")

class TwoFaAlreadyEnabledException(BadRequestException):
    def __init__(self, detail: str = "Bad Request"):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail="Two fa already enabled")

class TwoFaNotInitiatedException(BadRequestException):
    def __init__(self, detail: str = "Bad Request"):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail="Two fa not initiated")

class TwoFaNotEnabledException(BadRequestException):
    def __init__(self, detail: str = "Bad Request"):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail="Two fa not enabled")

class InvalidTokenException(BadRequestException):
    def __init__(self, detail: str = "Bad Request"):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token")

class WrongTokenTypeException(BadRequestException):
    def __init__(self, detail: str = "Bad Request"):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail="Wrong token type")

class RefreshTokenReuseException(BadRequestException):
    def __init__(self, detail: str = "Bad Request"):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail="Refresh token reuse")

class RefreshTokenRevokeOrExpiredException(BadRequestException):
    def __init__(self, detail: str = "Bad Request"):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail="Refresh token reused or expired")

class UsernameTakenException(BadRequestException):
    def __init__(self, detail: str = "Bad Request"):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail="Username taken")

class EmailTakenException(BadRequestException):
    def __init__(self, detail: str = "Bad Request"):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail="Email taken")


#####

class RefreshTokenRevokeFailedException(InternalServerErrorException):
    def __init__(self, detail: str = "Internal server error"):
        super().__init__(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Refresh token revoke failed")

class FailedToSentActivationEmailException(InternalServerErrorException):
    def __init__(self, detail: str = "Internal server error"):
        super().__init__(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to sent activation email")

class FailedToSentPasswordResetEmailException(InternalServerErrorException):
    def __init__(self, detail: str = "Internal server error"):
        super().__init__(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to sent password reset email")