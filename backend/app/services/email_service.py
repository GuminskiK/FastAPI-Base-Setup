from fastapi_mail import ConnectionConfig, FastMail, MessageSchema, MessageType
from pydantic import EmailStr

from app.core.config import settings
from app.core.logger.logger import get_logger

logger = get_logger(__name__)

conf = ConnectionConfig(
    MAIL_USERNAME=settings.MAIL_USERNAME or "test",
    MAIL_PASSWORD=settings.MAIL_PASSWORD or "test",
    MAIL_FROM=settings.MAIL_FROM,
    MAIL_PORT=settings.MAIL_PORT,
    MAIL_SERVER=settings.MAIL_SERVER,
    MAIL_STARTTLS=False,
    MAIL_SSL_TLS=False,
    USE_CREDENTIALS=bool(settings.MAIL_USERNAME and settings.MAIL_PASSWORD),
    VALIDATE_CERTS=False
)

fm = FastMail(conf)

async def send_activation_email(email_to: EmailStr, token: str):
    activation_link = f"{settings.FRONTEND_URL}/activate?token={token}"
    
    html_body = f"""
    <h3>Witaj!</h3>
    <p>Dziękujemy za rejestrację. Kliknij w poniższy link, aby aktywować swoje konto:</p>
    <p><a href="{activation_link}">{activation_link}</a></p>
    <br>
    <p>Link wygaśnie po 24 godzinach.</p>
    """

    message = MessageSchema(
        subject="Aktywuj swoje konto w aplikacji",
        recipients=[email_to],
        body=html_body,
        subtype=MessageType.html
    )
    
    try:
        await fm.send_message(message)
        logger.info("activation_email_sent_successfully", email=email_to)
    except Exception as e:
        logger.error("failed_to_send_activation_email", error=str(e), email=email_to)
        # Błąd logujemy, ale nie rzucamy HTTPException bo działa w BackgroundTasks
        # raise FailedToSentActivationEmailException()

async def send_password_reset_email(email_to: EmailStr, token: str):
    reset_link = f"{settings.FRONTEND_URL}/reset-password?token={token}"

    html_body = f"""
    <h3>Witaj!</h3>
    <p>Otrzymaliśmy prośbę o zmianę hasła dla Twojego konta.</p>
    <p>Kliknij w poniższy link, aby je zresetować:</p>
    <p><a href="{reset_link}">{reset_link}</a></p>
    <br>
    <p>Jeśli to nie Ty prosiłeś o zmianę, zignoruj tę wiadomość. Link wygaśnie po godzinie.</p>
    """

    message = MessageSchema(
        subject="Reset hasła",
        recipients=[email_to],
        body=html_body,
        subtype=MessageType.html
    )

    try:
        await fm.send_message(message)
        logger.info("password_reset_email_sent_successfully", email=email_to)
    except Exception as e:
        logger.error("failed_to_send_password_reset_email", error=str(e), email=email_to)
        # Błąd logujemy, ale nie rzucamy HTTPException bo działa w BackgroundTasks
        # raise FailedToSentPasswordResetEmailException()
