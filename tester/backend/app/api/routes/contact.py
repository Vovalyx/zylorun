import logging
from datetime import datetime, timezone
from fastapi import APIRouter, Request, HTTPException, Depends
from pydantic import BaseModel, EmailStr
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional

from app.database.session import get_db
from app.database.models import ContactMessage
from app.api.routes.admin import get_admin_user

logger = logging.getLogger(__name__)

router = APIRouter(tags=["contact"])

class ContactFormPayload(BaseModel):
    name: str
    email: EmailStr
    subject: str
    message: str

@router.post("/contact")
@router.post("/api/v1/contact")
async def submit_contact_form(
    payload: ContactFormPayload,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """Processes contact messages and inquiries from visitors and enterprise users."""
    try:
        clean_name = payload.name.strip()
        clean_email = payload.email.strip().lower()
        clean_subject = payload.subject.strip()
        clean_message = payload.message.strip()

        if not clean_name or not clean_email or not clean_message:
            raise HTTPException(status_code=400, detail="Name, valid email, and message are required.")

        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            client_ip = forwarded.split(",")[0].strip()
        elif request.client:
            client_ip = request.client.host
        else:
            client_ip = "unknown"

        msg_record = ContactMessage(
            name=clean_name,
            email=clean_email,
            subject=clean_subject or "General Inquiry",
            message=clean_message,
            ip_address=client_ip,
            created_at=datetime.now(timezone.utc).replace(tzinfo=None)
        )
        db.add(msg_record)
        await db.commit()
        await db.refresh(msg_record)

        logger.info(f"New contact inquiry #{msg_record.id} from {clean_email} ({clean_name}): {clean_subject}")

        return {
            "status": "success",
            "message": "Thank you for contacting ZyloRun & Vovalyx. We have received your message and will respond to your email within 4 to 12 hours.",
            "message_id": msg_record.id,
            "official_support_email": "zylorun.vovalyx@gmail.com"
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Failed to submit contact form")
        raise HTTPException(status_code=500, detail="Unable to process your inquiry right now. Please email directly to zylorun.vovalyx@gmail.com")

@router.get("/admin/contact-messages")
async def get_contact_messages(
    current_user: dict = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """Admin-only route to inspect inquiries submitted through the contact form."""
    try:
        res = await db.execute(select(ContactMessage).order_by(desc(ContactMessage.created_at)).limit(100))
        messages = res.scalars().all()
        return [
            {
                "id": m.id,
                "name": m.name,
                "email": m.email,
                "subject": m.subject,
                "message": m.message,
                "ip_address": m.ip_address,
                "created_at": m.created_at.isoformat() if m.created_at else None
            }
            for m in messages
        ]
    except Exception as exc:
        logger.exception("Failed to fetch contact messages")
        raise HTTPException(status_code=500, detail=str(exc))
