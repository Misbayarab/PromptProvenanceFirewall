
import pymupdf


def extract_text_from_pdf(pdf_path: str) -> str:
    """
    Extract text from every page of a PDF document.

    Args:
        pdf_path: Path to the PDF file.

    Returns:
        Extracted text as a single string.
    """
    extracted_text = []

    try:
        with pymupdf.open(pdf_path) as document:
            for page in document:
                text = page.get_text("text")
                if text.strip():
                    extracted_text.append(text)

    except Exception as exc:
        raise ValueError(
            f"Could not extract text from PDF: {exc}"
        ) from exc

    return "\n".join(extracted_text)
