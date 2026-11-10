"""File upload ingestion module supporting .eml and .msg files."""

import io
from typing import BinaryIO, Union
from active_verification.models.schemas import EmailMessage, IngestionSource
from active_verification.ingestion.parser import parser


class FileUploadIngestion:
    """Handles parsing uploaded email files (.eml, .msg)."""

    MAX_FILE_SIZE_BYTES = 25 * 1024 * 1024  # 25 MB limit

    @classmethod
    def ingest_bytes(cls, data: bytes, filename: str = "upload.eml") -> EmailMessage:
        """Ingest raw byte contents of an email file."""
        if len(data) > cls.MAX_FILE_SIZE_BYTES:
            raise ValueError(f"File size {len(data)} exceeds maximum allowed size ({cls.MAX_FILE_SIZE_BYTES} bytes)")

        return parser.parse_raw(data, source=IngestionSource.FILE_UPLOAD)

    @classmethod
    def ingest_stream(cls, stream: BinaryIO, filename: str = "upload.eml") -> EmailMessage:
        """Ingest a readable binary stream."""
        content = stream.read()
        return cls.ingest_bytes(content, filename=filename)


file_ingestion = FileUploadIngestion()

