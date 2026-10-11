import pymupdf


def extract_text_from_pdf(
    pdf_path: str
) -> str:

    document = pymupdf.open(pdf_path)

    extracted_text = []

    for page in document:

        text = page.get_text()

        extracted_text.append(text)

    document.close()

    return "\n".join(extracted_text)