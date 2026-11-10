"""Generic IMAP ingestion poller with SSL/TLS and message queue dispatch."""

import ssl
import imaplib
import logging
from typing import List, Optional, Callable
from active_verification.config import settings
from active_verification.models.schemas import EmailMessage, IngestionSource
from active_verification.ingestion.parser import parser

logger = logging.getLogger(__name__)


class IMAPPoller:
    """Polls an IMAP server for unread messages and dispatches them for analysis."""

    def __init__(
        self,
        server: Optional[str] = None,
        port: Optional[int] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        use_ssl: Optional[bool] = None,
        mailbox: Optional[str] = None,
    ):
        self.server = server or settings.IMAP_SERVER
        self.port = port or settings.IMAP_PORT
        self.username = username or settings.IMAP_USERNAME
        self.password = password or settings.IMAP_PASSWORD
        self.use_ssl = use_ssl if use_ssl is not None else settings.IMAP_USE_SSL
        self.mailbox = mailbox or settings.IMAP_MAILBOX

    def is_configured(self) -> bool:
        """Check if IMAP credentials are provided."""
        return bool(self.server and self.username and self.password)

    def fetch_unseen_messages(self, max_messages: int = 10) -> List[EmailMessage]:
        """Connect to IMAP server, fetch unread messages, parse them, and mark read."""
        if not self.is_configured():
            logger.info("IMAP poller is not configured; skipping remote fetch.")
            return []

        messages: List[EmailMessage] = []
        client = None
        try:
            if self.use_ssl:
                ssl_context = ssl.create_default_context()
                client = imaplib.IMAP4_SSL(self.server, self.port, ssl_context=ssl_context)
            else:
                client = imaplib.IMAP4(self.server, self.port)

            client.login(self.username, self.password)
            client.select(self.mailbox)

            # Search for unread messages
            typ, data = client.search(None, "UNSEEN")
            if typ != "OK" or not data[0]:
                return []

            msg_ids = data[0].split()[:max_messages]
            for m_id in msg_ids:
                typ, fetch_data = client.fetch(m_id, "(RFC822)")
                if typ != "OK":
                    continue

                for response_part in fetch_data:
                    if isinstance(response_part, tuple):
                        raw_email = response_part[1]
                        parsed_msg = parser.parse_raw(raw_email, source=IngestionSource.IMAP)
                        messages.append(parsed_msg)

            return messages
        except Exception as e:
            logger.error(f"Error fetching from IMAP server {self.server}: {e}")
            return []
        finally:
            if client:
                try:
                    client.close()
                    client.logout()
                except Exception:
                    pass


imap_poller = IMAPPoller()

