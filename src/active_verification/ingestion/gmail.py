"""Gmail API read-only OAuth ingestion poller."""

import base64
import logging
from typing import List, Optional, Dict, Any
from active_verification.config import settings
from active_verification.models.schemas import EmailMessage, IngestionSource
from active_verification.ingestion.parser import parser

logger = logging.getLogger(__name__)


class GmailIngestion:
    """Ingests emails from Gmail via read-only OAuth API."""

    READONLY_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"

    def __init__(
        self,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        refresh_token: Optional[str] = None,
    ):
        self.client_id = client_id or settings.GMAIL_CLIENT_ID
        self.client_secret = client_secret or settings.GMAIL_CLIENT_SECRET
        self.refresh_token = refresh_token or settings.GMAIL_REFRESH_TOKEN

    def is_configured(self) -> bool:
        """Verify whether Gmail API credentials are configured."""
        return bool(self.client_id and self.client_secret and self.refresh_token)

    def fetch_recent_messages(self, query: str = "is:unread", max_results: int = 10) -> List[EmailMessage]:
        """Fetch unread messages via Gmail REST API in raw RFC 822 format."""
        if not self.is_configured():
            logger.info("Gmail credentials not configured; skipping remote Gmail fetch.")
            return []

        try:
            import httpx

            # Refresh token to obtain access token
            token_url = "https://oauth2.googleapis.com/token"
            data = {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "refresh_token": self.refresh_token,
                "grant_type": "refresh_token",
            }
            with httpx.Client() as client:
                token_resp = client.post(token_url, data=data)
                token_resp.raise_for_status()
                access_token = token_resp.json().get("access_token")

                headers = {"Authorization": f"Bearer {access_token}"}

                # List messages
                list_url = "https://gmail.googleapis.com/gmail/v1/users/me/messages"
                params = {"q": query, "maxResults": max_results}
                resp = client.get(list_url, headers=headers, params=params)
                resp.raise_for_status()
                message_stubs = resp.json().get("messages", [])

                emails: List[EmailMessage] = []
                for stub in message_stubs:
                    m_id = stub.get("id")
                    msg_url = f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{m_id}"
                    msg_resp = client.get(msg_url, headers=headers, params={"format": "raw"})
                    if msg_resp.status_code == 200:
                        raw_b64 = msg_resp.json().get("raw", "")
                        # Decode urlsafe base64
                        raw_bytes = base64.urlsafe_b64decode(raw_b64.encode("utf-8"))
                        parsed = parser.parse_raw(raw_bytes, source=IngestionSource.GMAIL)
                        emails.append(parsed)

                return emails
        except Exception as e:
            logger.error(f"Gmail ingestion encountered error: {e}")
            return []


gmail_ingestion = GmailIngestion()

