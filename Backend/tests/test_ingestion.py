import pytest
from unittest.mock import MagicMock
from app.services.ingestion import extract_text_from_file

def test_extract_text_txt():
    content = b"This is a test threat alert."
    res = extract_text_from_file(content, "alert.txt")
    assert res == "This is a test threat alert."


def test_extract_text_csv():
    content = b"IP,Reputation,Context\n1.1.1.1,Malicious,C2 Server\n2.2.2.2,Suspicious,Phishing Site"
    res = extract_text_from_file(content, "iocs.csv")
    assert "IP | Reputation | Context" in res
    assert "1.1.1.1 | Malicious | C2 Server" in res
    assert "2.2.2.2 | Suspicious | Phishing Site" in res


def test_extract_text_json():
    # Valid JSON format
    content = b'{"ip": "1.1.1.1", "status": "malicious"}'
    res = extract_text_from_file(content, "report.json")
    assert '"ip": "1.1.1.1"' in res
    assert '"status": "malicious"' in res
    
    # Invalid JSON format (should fallback to raw text decoding)
    content = b'{"ip": "1.1.1.1", "status":'
    res = extract_text_from_file(content, "report.json")
    assert res == '{"ip": "1.1.1.1", "status":'


def test_unsupported_file_extension():
    content = b"random content"
    with pytest.raises(ValueError) as excinfo:
        extract_text_from_file(content, "payload.exe")
    assert "Unsupported file type: .exe" in str(excinfo.value)


def test_extract_text_pdf(mocker):
    # Mock PyPDF2 PdfReader
    mock_page = MagicMock()
    mock_page.extract_text.return_value = "PDF Page Content"
    
    mock_reader = MagicMock()
    mock_reader.pages = [mock_page]
    
    mocker.patch("app.services.ingestion.PdfReader", return_value=mock_reader)
    
    res = extract_text_from_file(b"%PDF-1.4...", "doc.pdf")
    assert res == "PDF Page Content"


def test_extract_text_docx(mocker):
    # Mock python-docx Document
    mock_para1 = MagicMock()
    mock_para1.text = "Paragraph 1"
    mock_para2 = MagicMock()
    mock_para2.text = "Paragraph 2"
    
    mock_doc = MagicMock()
    mock_doc.paragraphs = [mock_para1, mock_para2]
    
    mocker.patch("app.services.ingestion.Document", return_value=mock_doc)
    
    res = extract_text_from_file(b"ZIP...", "doc.docx")
    assert res == "Paragraph 1\nParagraph 2"
