import PyPDF2


def extract_text_from_pdf(file) -> str:
    """Extract text content from a PDF file.
    
    Args:
        file: A file-like object (Django UploadedFile or similar)
        
    Returns:
        Extracted text as a single string
        
    Raises:
        ValueError: If PDF cannot be read or is empty
    """
    try:
        reader = PyPDF2.PdfReader(file)
        if len(reader.pages) == 0:
            raise ValueError("PDF file is empty")
        
        text = ""
        for page_num, page in enumerate(reader.pages):
            page_text = page.extract_text()
            if page_text:
                text += page_text + "\n"
        
        text = text.strip()
        if not text:
            raise ValueError("Could not extract any text from PDF")
        
        return text
    except PyPDF2.errors.PdfReadError as e:
        raise ValueError(f"Invalid or corrupted PDF file: {e}")
    except Exception as e:
        raise ValueError(f"Failed to extract text from PDF: {e}")


def extract_text_from_txt(file) -> str:
    """Extract text content from a TXT file.
    
    Args:
        file: A file-like object (Django UploadedFile or similar)
        
    Returns:
        Text content as a single string
        
    Raises:
        ValueError: If TXT cannot be read
    """
    try:
        content = file.read()
        if isinstance(content, bytes):
            text = content.decode("utf-8", errors="replace")
        else:
            text = content
        
        text = text.strip()
        if not text:
            raise ValueError("TXT file is empty")
        
        return text
    except Exception as e:
        raise ValueError(f"Failed to extract text from TXT: {e}")