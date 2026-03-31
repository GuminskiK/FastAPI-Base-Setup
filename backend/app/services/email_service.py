from fastapi_mail import FastMail, MessageSchema, ConnectionConfig, MessageType
from pydantic import EmailStr
from app.core.config import settings
from app.core.logger import get_logger

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
