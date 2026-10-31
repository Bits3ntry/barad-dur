"""Minimal PDF writer (base-14 fonts, no dependencies).

Only what a security report needs: titled paragraphs, a two-column table and
page numbers. It deliberately avoids reportlab/weasyprint so the platform keeps
its zero-extra-dependency footprint; the tradeoff is no images, no rich layout
and Latin-1 text only (non-encodable characters degrade to '?').
"""
from __future__ import annotations

PAGE_WIDTH = 595
PAGE_HEIGHT = 842
MARGIN = 56
LEADING = 15
MAX_CHARS = 88


def _escape(text: str) -> str:
    text = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    return text.replace("\r", " ").replace("\n", " ")


# WinAnsi (cp1252) covers em dashes and middle dots; map the rest explicitly.
_GLYPHS = {"\u2014": "-", "\u2013": "-", "\u2192": "->", "\u2190": "<-",
           "\u2265": ">=", "\u2264": "<=", "\u2018": "'", "\u2019": "'",
           "\u201c": '"', "\u201d": '"', "\u2026": "...", "\u00b7": "\u00b7"}


def _latin(text: str) -> str:
    text = str(text)
    for source, target in _GLYPHS.items():
        text = text.replace(source, target)
    return text.encode("cp1252", "replace").decode("cp1252")


def wrap(text: str, width: int = MAX_CHARS) -> list[str]:
    words = _latin(text).split()
    if not words:
        return [""]
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if len(candidate) <= width:
            current = candidate
        else:
            if current:
                lines.append(current)
            while len(word) > width:
                lines.append(word[:width])
                word = word[width:]
            current = word
    if current:
        lines.append(current)
    return lines


class PdfReport:
    def __init__(self, title: str, subtitle: str = ""):
        self.title = _latin(title)
        self.subtitle = _latin(subtitle)
        self.lines: list[tuple[str, str, int]] = []  # (style, text, size)

    def heading(self, text: str, size: int = 15) -> "PdfReport":
        self.lines.append(("bold", text, size))
        return self

    def paragraph(self, text: str, size: int = 10) -> "PdfReport":
        for piece in wrap(text, int(MAX_CHARS * 11 / size)):
            self.lines.append(("regular", piece, size))
        return self

    def key_value(self, key: str, value: str) -> "PdfReport":
        self.lines.append(("bold", key, 10))
        self.paragraph(str(value))
        return self

    def table(self, header: list[str], rows: list[list[str]],
              widths: list[int]) -> "PdfReport":
        self.lines.append(("bold", "  ".join(
            head[:wid].ljust(wid) for head, wid in zip(header, widths)), 9))
        for row in rows:
            cells = []
            for value, wid in zip(row, widths):
                text = _latin(value if value is not None else "—")
                cells.append(text[:wid].ljust(wid))
            self.lines.append(("regular", "  ".join(cells), 9))
        return self

    def _pages(self) -> list[list[tuple[str, str, int]]]:
        available = PAGE_HEIGHT - 2 * MARGIN - 60
        per_page = max(10, available // LEADING)
        pages, current, used = [], [], 0
        for entry in self.lines:
            _, _, size = entry
            cost = max(1, LEADING / LEADING) if size <= 11 else 2
            if used + cost > per_page and current:
                pages.append(current)
                current, used = [], 0
            current.append(entry)
            used += cost
        if current:
            pages.append(current)
        return pages or [[("regular", "", 10)]]

    def build(self) -> bytes:
        pages = self._pages()
        objects: list[bytes] = []

        def add(payload: bytes) -> int:
            objects.append(payload)
            return len(objects)

        font_regular = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica "
                           b"/Encoding /WinAnsiEncoding >>")
        font_bold = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold "
                        b"/Encoding /WinAnsiEncoding >>")
        # content stream + page object are added per page before the tree
        pages_id_placeholder = len(objects) + 1 + 2 * len(pages)
        page_ids = []
        for number, page_lines in enumerate(pages, start=1):
            body = ["BT", f"1 0 0 1 {MARGIN} {PAGE_HEIGHT - MARGIN} Tm",
                    "/F2 15 Tf", f"0 -16 Td ({_escape(self.title)}) Tj",
                    "/F1 8 Tf", f"0 -12 Td ({_escape(self.subtitle)}) Tj",
                    "0 -22 Td"]
            for style, text, size in page_lines:
                gap = LEADING if size <= 11 else 24
                body.append(f"/{'F2' if style == 'bold' else 'F1'} {size} Tf")
                body.append(f"0 -{gap} Td ({_escape(text)}) Tj")
            body.append(f"/F1 8 Tf 0 -24 Td (Page {number} of {len(pages)}) Tj")
            body.append("ET")
            stream = "\n".join(body).encode("cp1252", "replace")
            content_id = add(b"<< /Length " + str(len(stream)).encode() +
                             b" >>\nstream\n" + stream + b"\nendstream")
            page_ids.append(add(
                (f"<< /Type /Page /Parent {pages_id_placeholder} 0 R /MediaBox "
                 f"[0 0 {PAGE_WIDTH} {PAGE_HEIGHT}] /Resources << /Font << /F1 "
                 f"{font_regular} 0 R /F2 {font_bold} 0 R >> >> /Contents "
                 f"{content_id} 0 R >>").encode()))
        kids = " ".join(f"{page_id} 0 R" for page_id in page_ids)
        pages_id = add((f"<< /Type /Pages /Count {len(page_ids)} /Kids [{kids}] >>")
                       .encode())
        assert pages_id == pages_id_placeholder, "page tree placeholder drifted"
        catalog_id = add((f"<< /Type /Catalog /Pages {pages_id} 0 R >>").encode())

        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = [0]
        for index, payload in enumerate(objects, start=1):
            offsets.append(len(out))
            out += f"{index} 0 obj\n".encode() + payload + b"\nendobj\n"
        xref_offset = len(out)
        out += f"xref\n0 {len(objects) + 1}\n".encode()
        out += b"0000000000 65535 f \n"
        for offset in offsets[1:]:
            out += f"{offset:010d} 00000 n \n".encode()
        out += (f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_id} 0 R >>\n"
                f"startxref\n{xref_offset}\n%%EOF\n").encode()
        return bytes(out)
