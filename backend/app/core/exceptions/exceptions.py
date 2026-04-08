from fastapi import HTTPException, status


class AppBaseException(HTTPException):
    """Base class for all app exceptions."""

    pass

class ResourceNotFoundException(AppBaseException):
    def __init__(self, resource_name: str = "Resource"):
        super().__init__(status_code=status.HTTP_404_NOT_FOUND, detail=f"{resource_name} not found")

class ForbiddenException(AppBaseException):
    def __init__(self, detail: str = "Not authorized to perform this action"):
        super().__init__(status_code=status.HTTP_403_FORBIDDEN, detail=detail)

class BadRequestException(AppBaseException):
    def __init__(self, detail: str = "Bad Request"):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)

class UnauthorizedException(AppBaseException):
    def __init__(self, detail: str = "Unauthorized"):
        super().__init__(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)

class InternalServerErrorException(AppBaseException):
    def __init__(self, detail: str = "Internal server error"):
        super().__init__(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=detail)
###########################

class SessionNotFoundException(ResourceNotFoundException):
    def __init__(self, resource_name: str = "Session"):
        super().__init__(resource_name=resource_name)

class UserNotFoundException(ResourceNotFoundException):
    def __init__(self, resource_name: str = "User"):
        super().__init__(resource_name=resource_name)

class ApiKeyNotFoundException(ResourceNotFoundException):
    def __init__(self, resource_name: str = "Apikey"):
        super().__init__(resource_name=resource_name)
##########################

class AdminForibiddenFromCreatingApiKeyException(ForbiddenException):
    def __init__(self, detail: str = "Not authorized to perform this action"):
        super().__init__(detail="Admin is forbidden from creating api keys")

class AdminNeededException(ForbiddenException):
    def __init__(self, detail: str = "Not authorized to perform this action"):
        super().__init__(detail="Only admin can perform this action")

class AdminOrOwnerNeededException(ForbiddenException):
    def __init__(self, detail: str = "Not authorized to perform this action"):
        super().__init__(detail="Only admin or owner can perform this action")


#########################

class TwoFaAlreadyEnabledException(BadRequestException):
    def __init__(self, detail: str = "Bad Request"):
        super().__init__(detail="2FA is already enabled")

class TwoFaNotInitiatedException(BadRequestException):
    def __init__(self, detail: str = "Bad Request"):
        super().__init__(detail="2FA setup not initiated")

class TwoFaNotEnabledException(BadRequestException):
    def __init__(self, detail: str = "Bad Request"):
        super().__init__(detail="2FA is not enabled")

class InvalidTokenException(BadRequestException):
    def __init__(self, detail: str = "Bad Request"):
        super().__init__(detail="Invalid token")

class WrongTokenTypeException(BadRequestException):
    def __init__(self, detail: str = "Bad Request"):
        super().__init__(detail="Wrong token type")

class UsernameTakenException(BadRequestException):
    def __init__(self, detail: str = "Bad Request"):
        super().__init__(detail="Username taken")

class EmailTakenException(BadRequestException):
    def __init__(self, detail: str = "Bad Request"):
        super().__init__(detail="Email taken")


####

class Invalid2FACodeException(UnauthorizedException):
    def __init__(self, detail: str = "Unauthorized"):
        super().__init__(detail="Invalid 2FA code")

class Required2FACodeException(UnauthorizedException):
    def __init__(self, detail: str = "Unauthorized"):
        super().__init__(detail="Required 2FA code")

class InvalidCredentialsException(UnauthorizedException):
    def __init__(self, detail: str = "Unauthorized"):
        super().__init__(detail="Invalid credentials")

class RefreshTokenReuseException(UnauthorizedException):
    def __init__(self, detail: str = "Unauthorized"):
        super().__init__(detail="Refresh token reuse detected; all sessions revoked")

class RefreshTokenRevokeOrExpiredException(UnauthorizedException):
    def __init__(self, detail: str = "Unauthorized"):
        super().__init__(detail="Refresh token reused or expired")

class RefreshTokenRevokeFailedException(UnauthorizedException):
    def __init__(self, detail: str = "Unauthorized"):
        super().__init__(detail="Refresh token revoke failed")

#####
class FailedToSentActivationEmailException(InternalServerErrorException):
    def __init__(self, detail: str = "Internal server error"):
        super().__init__(detail="Failed to sent activation email")

class FailedToSentPasswordResetEmailException(InternalServerErrorException):
    def __init__(self, detail: str = "Internal server error"):
        super().__init__(detail="Failed to sent password reset email")