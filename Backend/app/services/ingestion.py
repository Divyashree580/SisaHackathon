import csv
import io
import json
import logging
import re
from PyPDF2 import PdfReader
from docx import Document

logger = logging.getLogger(__name__)


def extract_text_from_file(file_bytes: bytes, filename: str) -> str:
    """
    Extracts raw text from various document formats.
    Supported: pdf, docx, doc, txt, csv, json.
    Raises ValueError with descriptive message on extraction failure.
    """
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    try:
        if ext == "txt":
            return _normalize_text(file_bytes.decode("utf-8", errors="ignore"))

        elif ext == "pdf":
            pdf_file = io.BytesIO(file_bytes)
            reader = PdfReader(pdf_file)
            text = []
            for page in reader.pages:
                page_text = page.extract_text()
                if page_text:
                    text.append(page_text)
            return _normalize_text("\n".join(text))

        elif ext == "docx":
            docx_file = io.BytesIO(file_bytes)
            doc = Document(docx_file)
            text = [paragraph.text for paragraph in doc.paragraphs]
            return _normalize_text("\n".join(text))

        elif ext == "doc":
            return _extract_doc(file_bytes)

        elif ext == "csv":
            csv_file = io.StringIO(file_bytes.decode("utf-8", errors="ignore"))
            reader = csv.reader(csv_file)
            rows = [" | ".join(row) for row in reader]
            return _normalize_text("\n".join(rows))

        elif ext == "json":
            try:
                data = json.loads(file_bytes.decode("utf-8", errors="ignore"))
                return _normalize_text(json.dumps(data, indent=2))
            except json.JSONDecodeError:
                return _normalize_text(file_bytes.decode("utf-8", errors="ignore"))

        else:
            raise ValueError(
                f"Unsupported file type: .{ext}. "
                "Supported formats: PDF, DOC, DOCX, TXT, CSV, JSON"
            )

    except ValueError:
        raise
    except Exception as e:
        raise ValueError(f"Failed to parse {ext} file '{filename}': {str(e)}")


def _extract_doc(file_bytes: bytes) -> str:
    """
    Extracts text from legacy .doc (OLE2 binary) format using doc2txt.
    doc2txt requires a file path, so we write to a temp file.
    """
    import tempfile
    import os

    try:
        import doc2txt
    except ImportError:
        raise ValueError(
            "doc2txt package is not installed. "
            "Install it with: pip install doc2txt"
        )

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".doc", delete=False) as tmp:
            tmp.write(file_bytes)
            tmp_path = tmp.name

        text = doc2txt.process(tmp_path)
        return _normalize_text(text if text else "")
    except Exception as e:
        raise ValueError(f"Failed to extract text from .doc file: {str(e)}")
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)


def _normalize_text(text: str) -> str:
    """
    Cleans up extracted text:
    - Remove null bytes
    - Collapse excessive newlines
    - Strip leading/trailing whitespace
    """
    text = text.replace("\x00", "")
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()
