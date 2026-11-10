"""RFC 822 and MIME email parser with URL and attachment extraction."""

import re
import email
from email import policy
from email.message import EmailMessage as PyEmailMessage
import hashlib
from typing import List, Tuple, Optional, Any
from bs4 import BeautifulSoup

from active_verification.models.schemas import (
    EmailMessage,
    EmailHeader,
    EmailAuthResults,
    AuthStatus,
    ReceivedHop,
    ExtractedURL,
    EmailAttachment,
    IngestionSource,
)


class RFC822Parser:
    """Parses raw RFC 822 / MIME emails into structured EmailMessage objects."""

    def __init__(self):
        self._url_regex = re.compile(
            r'https?://(?:[a-zA-Z0-9-._~:/?#\[\]@!$&\'()*+,;=]|%[0-9a-fA-F]{2})+'
        )
        self._ip_regex = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

    def parse_raw(self, raw_bytes: bytes, source: IngestionSource = IngestionSource.FILE_UPLOAD) -> EmailMessage:
        """Parse raw email bytes into an EmailMessage model."""
        raw_sha256 = hashlib.sha256(raw_bytes).hexdigest()
        msg_id = f"msg_{raw_sha256[:16]}"

        # Check for Outlook OLE .MSG header
        if raw_bytes.startswith(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'):
            return self._parse_msg_compound(raw_bytes, msg_id, raw_sha256, source)

        try:
            py_msg = email.message_from_bytes(raw_bytes, policy=policy.default)
        except Exception:
            # Fallback to compat32 policy if default fails on malformed content
            py_msg = email.message_from_bytes(raw_bytes, policy=policy.compat32)

        # Extract headers
        headers = self._extract_headers(py_msg)

        # Extract body parts
        body_plain, body_html = self._extract_bodies(py_msg)

        # Extract attachments
        attachments = self._extract_attachments(py_msg)

        # Extract URLs from HTML and plain text
        urls = self._extract_urls(body_plain, body_html)

        return EmailMessage(
            id=msg_id,
            source=source,
            raw_sha256=raw_sha256,
            headers=headers,
            body_plain=body_plain,
            body_html=body_html,
            urls=urls,
            attachments=attachments,
            raw_size_bytes=len(raw_bytes),
            received_at=headers.date
        )

    def _extract_headers(self, msg: Any) -> EmailHeader:
        """Extract and structure email headers."""
        from_raw = str(msg.get("From", "") or "")
        from_name = ""
        from_address = ""

        # Parse From: "Name" <user@domain.com>
        addr_match = re.search(r'<\s*([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,})\s*>', from_raw)
        if addr_match:
            from_address = addr_match.group(1).lower().strip()
            name_part = from_raw[:addr_match.start()].strip()
            from_name = name_part.strip(' "“\'')
        else:
            raw_clean = from_raw.strip().lower()
            if "@" in raw_clean:
                from_address = raw_clean
            from_name = from_raw.strip(' "“\'')

        from_domain = from_address.split("@")[-1] if "@" in from_address else ""

        reply_to_raw = str(msg.get("Reply-To", "") or "")
        reply_to = None
        if reply_to_raw:
            rt_match = re.search(r'<\s*([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,})\s*>', reply_to_raw)
            reply_to = rt_match.group(1).lower().strip() if rt_match else reply_to_raw.strip()

        return_path_raw = str(msg.get("Return-Path", "") or "")
        return_path = None
        if return_path_raw:
            rp_match = re.search(r'<\s*([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,})\s*>', return_path_raw)
            return_path = rp_match.group(1).lower().strip() if rp_match else return_path_raw.strip()

        to_raw = msg.get_all("To", []) if hasattr(msg, "get_all") else [msg.get("To", "")]
        to_list = [str(t).strip() for t in to_raw if t]

        cc_raw = msg.get_all("Cc", []) if hasattr(msg, "get_all") else [msg.get("Cc", "")]
        cc_list = [str(c).strip() for c in cc_raw if c]

        subject = str(msg.get("Subject", "") or "")
        date = str(msg.get("Date", "") or "")
        message_id = str(msg.get("Message-ID", "") or "")

        # Authentication-Results
        auth_results = self._parse_authentication_results(msg)

        # Received hops
        received_hops = self._parse_received_hops(msg)

        return EmailHeader(
            from_raw=from_raw,
            from_name=from_name,
            from_address=from_address,
            from_domain=from_domain,
            reply_to=reply_to,
            return_path=return_path,
            to=to_list,
            cc=cc_list,
            subject=subject,
            date=date,
            message_id=message_id,
            auth_results=auth_results,
            received_hops=received_hops,
        )

    def _parse_authentication_results(self, msg: Any) -> EmailAuthResults:
        """Parse Authentication-Results header for SPF, DKIM, and DMARC."""
        auth_header = str(msg.get("Authentication-Results", "") or "")
        results = EmailAuthResults(raw_header=auth_header if auth_header else None)

        if not auth_header:
            # Check individual headers like Received-SPF
            rec_spf = str(msg.get("Received-SPF", "") or "")
            if rec_spf:
                first_word = rec_spf.split()[0].lower() if rec_spf.split() else ""
                results.spf = self._map_auth_status(first_word)
                results.spf_details = rec_spf
            return results

        lower_header = auth_header.lower()

        # Parse SPF
        spf_m = re.search(r'spf=(\w+)(?:\s+\(([^)]+)\))?', lower_header)
        if spf_m:
            results.spf = self._map_auth_status(spf_m.group(1))
            results.spf_details = spf_m.group(2) or spf_m.group(1)

        # Parse DKIM
        dkim_m = re.search(r'dkim=(\w+)(?:\s+\(([^)]+)\))?', lower_header)
        if dkim_m:
            results.dkim = self._map_auth_status(dkim_m.group(1))
            results.dkim_details = dkim_m.group(2) or dkim_m.group(1)

        # Parse DMARC
        dmarc_m = re.search(r'dmarc=(\w+)(?:\s+\(([^)]+)\))?', lower_header)
        if dmarc_m:
            results.dmarc = self._map_auth_status(dmarc_m.group(1))
            results.dmarc_details = dmarc_m.group(2) or dmarc_m.group(1)

        return results

    def _map_auth_status(self, raw_status: str) -> AuthStatus:
        status_map = {
            "pass": AuthStatus.PASS,
            "fail": AuthStatus.FAIL,
            "softfail": AuthStatus.SOFTFAIL,
            "neutral": AuthStatus.NEUTRAL,
            "none": AuthStatus.NONE,
            "temperror": AuthStatus.TEMPERROR,
            "permerror": AuthStatus.PERMERROR,
        }
        return status_map.get(raw_status.strip(), AuthStatus.NONE)

    def _parse_received_hops(self, msg: Any) -> List[ReceivedHop]:
        """Extract and structure the Received: header chain."""
        received_headers = msg.get_all("Received", []) if hasattr(msg, "get_all") else []
        if not received_headers and msg.get("Received"):
            received_headers = [msg.get("Received")]

        hops: List[ReceivedHop] = []
        for raw in received_headers:
            raw_str = str(raw)
            # Find IP address
            ip_m = self._ip_regex.search(raw_str)
            ip = ip_m.group(0) if ip_m else None

            # Split 'from ... by ... ; timestamp'
            from_part = None
            by_part = None
            ts_part = None

            if ";" in raw_str:
                parts = raw_str.split(";", 1)
                routing_part = parts[0]
                ts_part = parts[1].strip()
            else:
                routing_part = raw_str

            from_m = re.search(r'from\s+([^\s;]+)', routing_part, re.IGNORECASE)
            if from_m:
                from_part = from_m.group(1)

            by_m = re.search(r'by\s+([^\s;]+)', routing_part, re.IGNORECASE)
            if by_m:
                by_part = by_m.group(1)

            hops.append(ReceivedHop(
                from_server=from_part,
                by=by_part,
                ip=ip,
                timestamp=ts_part
            ))
        return hops

    def _extract_bodies(self, msg: Any) -> Tuple[str, str]:
        """Extract plain text and HTML representations."""
        plain_parts: List[str] = []
        html_parts: List[str] = []

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))

                # Skip attachments
                if "attachment" in content_disposition.lower():
                    continue

                try:
                    payload = part.get_payload(decode=True)
                    if payload is None:
                        continue
                    charset = part.get_content_charset() or "utf-8"
                    decoded = payload.decode(charset, errors="replace")
                except Exception:
                    decoded = str(part.get_payload() or "")

                if content_type == "text/plain":
                    plain_parts.append(decoded)
                elif content_type == "text/html":
                    html_parts.append(decoded)
        else:
            content_type = msg.get_content_type()
            try:
                payload = msg.get_payload(decode=True)
                charset = msg.get_content_charset() or "utf-8"
                decoded = payload.decode(charset, errors="replace") if payload else ""
            except Exception:
                decoded = str(msg.get_payload() or "")

            if content_type == "text/html":
                html_parts.append(decoded)
            else:
                plain_parts.append(decoded)

        return "\n".join(plain_parts), "\n".join(html_parts)

    def _extract_attachments(self, msg: Any) -> List[EmailAttachment]:
        """Extract and inspect attachments."""
        attachments: List[EmailAttachment] = []

        if not msg.is_multipart():
            return attachments

        for part in msg.walk():
            content_disposition = str(part.get("Content-Disposition", ""))
            filename = part.get_filename()

            if not filename and "attachment" not in content_disposition.lower():
                continue

            filename = filename or "unnamed_attachment"
            payload = part.get_payload(decode=True) or b""
            mime_type = part.get_content_type() or "application/octet-stream"
            size_bytes = len(payload)
            sha256 = hashlib.sha256(payload).hexdigest()

            # Analyze extension and risk
            ext = ""
            if "." in filename:
                ext = filename.rsplit(".", 1)[-1].lower()

            is_executable = ext in {
                "exe", "bat", "cmd", "scr", "vbs", "js", "ps1", "sh", "pif", "cpl", "hta", "jar"
            }
            has_macros = ext in {"docm", "xlsm", "pptm", "dotm", "xltm", "xlam"}
            is_archive = ext in {"zip", "rar", "7z", "tar", "gz", "iso", "img"}

            # Double extension check (e.g. invoice.pdf.exe)
            parts = filename.split(".")
            is_double_ext = len(parts) >= 3 and parts[-1].lower() in {"exe", "scr", "vbs", "bat", "js"}

            risk_reasons: List[str] = []
            risk_score = 0.0

            if is_double_ext:
                risk_score = max(risk_score, 0.95)
                risk_reasons.append(f"Deceptive double extension detected in '{filename}'")
            if is_executable:
                risk_score = max(risk_score, 0.90)
                risk_reasons.append(f"Directly executable file type: .{ext}")
            if has_macros:
                risk_score = max(risk_score, 0.75)
                risk_reasons.append(f"Macro-enabled document format: .{ext}")
            if is_archive:
                risk_score = max(risk_score, 0.40)
                risk_reasons.append(f"Compressed archive container: .{ext}")

            # Magic bytes check for hidden executable in spoofed extension
            if payload.startswith(b"MZ") and not is_executable:
                risk_score = max(risk_score, 0.98)
                risk_reasons.append("Windows PE executable magic bytes (MZ) detected in non-executable filename")

            attachments.append(EmailAttachment(
                filename=filename,
                mime_type=mime_type,
                size_bytes=size_bytes,
                sha256=sha256,
                extension=ext,
                is_executable=is_executable,
                has_macros=has_macros,
                is_archive=is_archive,
                is_double_extension=is_double_ext,
                risk_score=risk_score,
                risk_reasons=risk_reasons,
            ))

        return attachments

    def _extract_urls(self, body_plain: str, body_html: str) -> List[ExtractedURL]:
        """Extract URLs from HTML anchor tags and plain text with mismatch detection."""
        extracted: List[ExtractedURL] = []
        seen_urls = set()

        # Parse HTML anchors
        if body_html:
            try:
                soup = BeautifulSoup(body_html, "html.parser")
                for a_tag in soup.find_all("a", href=True):
                    href = a_tag["href"].strip()
                    display_text = a_tag.get_text().strip()
                    if not href or href.startswith("mailto:") or href.startswith("javascript:"):
                        continue

                    # Check for hidden text tricks (e.g. font-size: 0px or opacity: 0)
                    has_hidden = False
                    style = a_tag.get("style", "").lower()
                    if "display:none" in style or "font-size:0" in style or "opacity:0" in style:
                        has_hidden = True

                    url_obj = self._build_url_object(href, display_text, has_hidden)
                    extracted.append(url_obj)
                    seen_urls.add(href)
            except Exception:
                pass

        # Parse plain text URLs
        if body_plain:
            for match in self._url_regex.finditer(body_plain):
                url_str = match.group(0).strip(".,;:()[]'\"")
                if url_str not in seen_urls:
                    url_obj = self._build_url_object(url_str, url_str, False)
                    extracted.append(url_obj)
                    seen_urls.add(url_str)

        return extracted

    def _build_url_object(self, href: str, display_text: str, has_hidden: bool) -> ExtractedURL:
        """Analyze individual link for href vs text mismatch, raw IP, punycode, etc."""
        domain = ""
        domain_match = re.search(r'https?://([^/:\s?#]+)', href, re.IGNORECASE)
        if domain_match:
            domain = domain_match.group(1).lower()

        # Check raw IP
        is_ip = bool(self._ip_regex.match(domain))

        # Check Punycode / IDN
        punycode = None
        if "xn--" in domain:
            punycode = domain

        # Check URL shorteners
        shorteners = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly", "is.gd", "rb.gy"}
        is_shortener = domain in shorteners

        # Link text != href check
        href_mismatch = False
        reasons: List[str] = []
        risk_score = 0.0

        if display_text and ("http://" in display_text or "https://" in display_text or ".com" in display_text or ".org" in display_text or ".net" in display_text):
            # Extract claimed domain from display text
            disp_match = re.search(r'(?:https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', display_text)
            if disp_match:
                claimed_domain = disp_match.group(1).lower()
                if claimed_domain != domain and not domain.endswith("." + claimed_domain):
                    href_mismatch = True
                    risk_score = max(risk_score, 0.90)
                    reasons.append(f"Deceptive link text: displays '{claimed_domain}' but leads to '{domain}'")

        if is_ip:
            risk_score = max(risk_score, 0.75)
            reasons.append(f"Link points directly to raw IP address ({domain}) instead of domain name")

        if punycode:
            risk_score = max(risk_score, 0.85)
            reasons.append(f"Internationalized Punycode domain detected: '{punycode}' (potential homograph attack)")

        if is_shortener:
            risk_score = max(risk_score, 0.50)
            reasons.append(f"URL shortener '{domain}' obscures ultimate destination")

        if has_hidden:
            risk_score = max(risk_score, 0.80)
            reasons.append("Hidden CSS styling detected in anchor tag")

        return ExtractedURL(
            original_url=href,
            display_text=display_text,
            domain=domain,
            punycode_domain=punycode,
            is_ip_address=is_ip,
            is_shortener=is_shortener,
            href_mismatch=href_mismatch,
            has_hidden_text=has_hidden,
            risk_score=risk_score,
            reasons=reasons,
        )

    def _parse_msg_compound(self, raw_bytes: bytes, msg_id: str, raw_sha256: str, source: IngestionSource) -> EmailMessage:
        """Handle Outlook .MSG OLE format by extracting readable strings gracefully."""
        # Simple string-stream extractor for .msg when compound storage tools aren't present
        text_content = raw_bytes.decode("latin-1", errors="ignore")

        subj_m = re.search(r'__substg1\.0_0037001[EF](.*?)\x00', text_content)
        subject = subj_m.group(1) if subj_m else "Outlook Message"

        body_m = re.search(r'__substg1\.0_1000001[EF](.*?)\x00', text_content)
        body = body_m.group(1) if body_m else text_content[:2000]

        headers = EmailHeader(
            from_raw="outlook-msg-user@local",
            from_name="Outlook Sender",
            from_address="sender@msg.local",
            from_domain="msg.local",
            subject=subject,
        )

        urls = self._extract_urls(body, "")

        return EmailMessage(
            id=msg_id,
            source=source,
            raw_sha256=raw_sha256,
            headers=headers,
            body_plain=body,
            body_html="",
            urls=urls,
            attachments=[],
            raw_size_bytes=len(raw_bytes),
        )


parser = RFC822Parser()
