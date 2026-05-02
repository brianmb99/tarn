#!/usr/bin/env python3
"""Generate human-readable PDFs from the canonical markdown docs.

Single source of truth: the .md files. The earlier generator hard-coded
the content in Python and drifted every time the markdown changed; this
script reads markdown directly so the PDFs can never disagree with the
source. Re-run any time docs change.

Run:
    python tools/generate-docs-pdf.py             # all three
    python tools/generate-docs-pdf.py --only sdk
    python tools/generate-docs-pdf.py --only architecture protocol

Outputs (under docs/):
    tarn-sdk-guide.pdf            — App developer guide (from client/README.md)
    tarn-architecture-guide.pdf   — Architecture + internals (from docs/SDK_ARCHITECTURE.md)
    tarn-protocol.pdf             — Wire protocol spec (from docs/TARN_PROTOCOL.md)

Requires: reportlab, markdown-it-py.

    python -m pip install reportlab markdown-it-py
"""

from __future__ import annotations

import argparse
import html
from datetime import date
from pathlib import Path
from typing import Iterable

from markdown_it import MarkdownIt
from markdown_it.token import Token
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    KeepTogether,
    PageBreak,
    PageTemplate,
    Paragraph,
    Preformatted,
    Spacer,
    Table,
    TableStyle,
)


# ============ Doc registry ============
#
# One entry per PDF the script generates. `source` is relative to the repo
# root; `output` goes under docs/. `subtitle` and `tagline` show on the
# cover page.

REPO_ROOT = Path(__file__).resolve().parent.parent

DOCS = [
    {
        'name': 'sdk',
        'source': REPO_ROOT / 'client' / 'README.md',
        'output': REPO_ROOT / 'docs' / 'tarn-sdk-guide.pdf',
        'subtitle': 'SDK Guide',
        'tagline': 'Building apps on permanent, encrypted, user-owned data',
        'footer': 'Tarn SDK Guide',
    },
    {
        'name': 'architecture',
        'source': REPO_ROOT / 'docs' / 'SDK_ARCHITECTURE.md',
        'output': REPO_ROOT / 'docs' / 'tarn-architecture-guide.pdf',
        'subtitle': 'Architecture & Internals',
        'tagline': 'Schema-first design, branded crypto types, strict TypeScript',
        'footer': 'Tarn Architecture Guide',
    },
    {
        'name': 'protocol',
        'source': REPO_ROOT / 'docs' / 'TARN_PROTOCOL.md',
        'output': REPO_ROOT / 'docs' / 'tarn-protocol.pdf',
        'subtitle': 'Protocol Specification',
        'tagline': 'Wire format, key hierarchy, storage layout',
        'footer': 'Tarn Protocol Specification',
    },
]


# ============ Styles ============

def make_styles():
    base = getSampleStyleSheet()
    body_color = colors.HexColor('#1a1a1a')
    accent = colors.HexColor('#2c5f2d')  # muted green — Tarn / alpinism cue
    muted = colors.HexColor('#6b6b6b')
    code_bg = colors.HexColor('#f4f4f2')
    code_border = colors.HexColor('#dcdcd5')

    return {
        'Title': ParagraphStyle(
            'Title', parent=base['Title'],
            fontName='Helvetica-Bold', fontSize=42, leading=48,
            textColor=accent, alignment=TA_CENTER, spaceAfter=18,
        ),
        'Subtitle': ParagraphStyle(
            'Subtitle', parent=base['Normal'],
            fontName='Helvetica', fontSize=18, leading=22,
            textColor=body_color, alignment=TA_CENTER, spaceAfter=8,
        ),
        'Tagline': ParagraphStyle(
            'Tagline', parent=base['Normal'],
            fontName='Helvetica-Oblique', fontSize=12, leading=16,
            textColor=muted, alignment=TA_CENTER, spaceAfter=24,
        ),
        'Date': ParagraphStyle(
            'Date', parent=base['Normal'],
            fontName='Helvetica', fontSize=11, leading=14,
            textColor=muted, alignment=TA_CENTER,
        ),
        'H1': ParagraphStyle(
            'H1', parent=base['Heading1'],
            fontName='Helvetica-Bold', fontSize=20, leading=24,
            textColor=accent, spaceBefore=20, spaceAfter=12,
            keepWithNext=True,
        ),
        'H2': ParagraphStyle(
            'H2', parent=base['Heading2'],
            fontName='Helvetica-Bold', fontSize=14, leading=18,
            textColor=body_color, spaceBefore=14, spaceAfter=6,
            keepWithNext=True,
        ),
        'H3': ParagraphStyle(
            'H3', parent=base['Heading3'],
            fontName='Helvetica-Bold', fontSize=11.5, leading=15,
            textColor=body_color, spaceBefore=10, spaceAfter=4,
            keepWithNext=True,
        ),
        'H4': ParagraphStyle(
            'H4', parent=base['Heading3'],
            fontName='Helvetica-Bold', fontSize=10.5, leading=14,
            textColor=muted, spaceBefore=8, spaceAfter=3,
            keepWithNext=True,
        ),
        'Body': ParagraphStyle(
            'Body', parent=base['Normal'],
            fontName='Helvetica', fontSize=10.5, leading=15,
            textColor=body_color, alignment=TA_JUSTIFY, spaceAfter=8,
        ),
        'Bullet': ParagraphStyle(
            'Bullet', parent=base['Normal'],
            fontName='Helvetica', fontSize=10.5, leading=15,
            textColor=body_color, leftIndent=18, bulletIndent=4,
            spaceAfter=4,
        ),
        'BulletNested': ParagraphStyle(
            'BulletNested', parent=base['Normal'],
            fontName='Helvetica', fontSize=10.5, leading=15,
            textColor=body_color, leftIndent=36, bulletIndent=22,
            spaceAfter=3,
        ),
        'Code': ParagraphStyle(
            'Code', parent=base['Code'],
            fontName='Courier', fontSize=8.5, leading=12,
            textColor=body_color, backColor=code_bg, borderColor=code_border,
            borderWidth=0.5, borderPadding=8, leftIndent=0, rightIndent=0,
            spaceBefore=6, spaceAfter=10,
        ),
        'Quote': ParagraphStyle(
            'Quote', parent=base['Normal'],
            fontName='Helvetica-Oblique', fontSize=10, leading=14,
            textColor=accent, leftIndent=14, rightIndent=14,
            spaceBefore=6, spaceAfter=10,
        ),
        'TocEntry': ParagraphStyle(
            'TocEntry', parent=base['Normal'],
            fontName='Helvetica', fontSize=11, leading=18,
            textColor=body_color, leftIndent=8,
        ),
        'TocSub': ParagraphStyle(
            'TocSub', parent=base['Normal'],
            fontName='Helvetica', fontSize=10, leading=15,
            textColor=muted, leftIndent=24,
        ),
    }


# ============ Inline rendering ============
#
# markdown-it produces a flat token stream where block tokens (paragraph,
# heading) carry an "inline" child token. The inline token's `children`
# list holds the actual text + formatting marks. We walk those into a
# reportlab markup string (a small subset of HTML the platypus Paragraph
# renderer understands).

CODE_BG = '#f4f4f2'


def render_inline(token: Token) -> str:
    """Convert an inline token's children into reportlab markup."""
    if token.children is None:
        return html.escape(token.content)
    out = []
    # Stack of close-tags for link_open's, in matching order. We only emit
    # <link>...</link> when the href is absolute; otherwise the link becomes
    # underlined text only.
    link_close_stack: list[str] = []
    for child in token.children:
        t = child.type
        if t == 'text':
            out.append(html.escape(child.content))
        elif t == 'strong_open':
            out.append('<b>')
        elif t == 'strong_close':
            out.append('</b>')
        elif t == 'em_open':
            out.append('<i>')
        elif t == 'em_close':
            out.append('</i>')
        elif t == 's_open':
            out.append('<strike>')
        elif t == 's_close':
            out.append('</strike>')
        elif t == 'code_inline':
            # Inline code: monospace + light tinted background, no border (the
            # border attribute on <font> renders awkwardly mid-paragraph).
            text = html.escape(child.content)
            out.append(
                f'<font name="Courier" size="9" backColor="{CODE_BG}">'
                f'&nbsp;{text}&nbsp;</font>'
            )
        elif t == 'link_open':
            # reportlab's <link> only accepts absolute URLs (http/https/mailto)
            # or in-document bookmarks. Relative links from cross-doc references
            # (../foo.md, #section, etc.) raise at render time, so we render
            # those as plain underlined text and only emit <link> for absolute
            # URLs.
            href = next((v for k, v in (child.attrs or {}).items() if k == 'href'), '')
            absolute = bool(href) and (
                href.startswith('http://')
                or href.startswith('https://')
                or href.startswith('mailto:')
            )
            if absolute:
                out.append(f'<link href="{html.escape(href)}" color="#2c5f2d"><u>')
                link_close_stack.append('</u></link>')
            else:
                out.append('<u>')
                link_close_stack.append('</u>')
        elif t == 'link_close':
            out.append(link_close_stack.pop() if link_close_stack else '</u>')
        elif t == 'softbreak':
            out.append(' ')
        elif t == 'hardbreak':
            out.append('<br/>')
        elif t == 'image':
            # We don't embed inline images. Show alt text in italics.
            alt = html.escape(child.content)
            out.append(f'<i>[image: {alt}]</i>' if alt else '<i>[image]</i>')
        # Ignore anything else (HTML inline, etc.)
    return ''.join(out)


def render_inline_plain(token: Token) -> str:
    """Strip all marks from an inline token — used for TOC / link text."""
    if token.children is None:
        return token.content
    out = []
    for child in token.children:
        if child.type == 'text' or child.type == 'code_inline':
            out.append(child.content)
        elif child.type in ('softbreak', 'hardbreak'):
            out.append(' ')
    return ''.join(out)


# ============ Block walker ============

class Walker:
    """Walk a markdown-it token stream and emit Platypus flowables.

    Stateful for two reasons:
      - list nesting (we render each item as a single Paragraph but need to
        track indentation depth for nested bullets)
      - TOC accumulation (collected during the walk so the cover/TOC page
        can be assembled before the body even though we render in order)
    """

    def __init__(self, styles):
        self.styles = styles
        self.story: list = []
        self.toc: list = []  # [(level, plain_text)]
        self._list_depth = 0

    def walk(self, tokens: list[Token]) -> None:
        i = 0
        while i < len(tokens):
            i = self._dispatch(tokens, i)

    def _dispatch(self, tokens: list[Token], i: int) -> int:
        t = tokens[i]
        kind = t.type

        if kind == 'heading_open':
            return self._handle_heading(tokens, i)
        if kind == 'paragraph_open':
            return self._handle_paragraph(tokens, i)
        if kind in ('fence', 'code_block'):
            return self._handle_code_block(tokens, i)
        if kind == 'bullet_list_open':
            return self._handle_list(tokens, i, ordered=False)
        if kind == 'ordered_list_open':
            return self._handle_list(tokens, i, ordered=True)
        if kind == 'hr':
            self.story.append(Spacer(1, 0.15 * inch))
            return i + 1
        if kind == 'table_open':
            return self._handle_table(tokens, i)
        if kind == 'blockquote_open':
            return self._handle_blockquote(tokens, i)
        # Skip everything else (HTML blocks, list_item bookkeeping, etc.)
        return i + 1

    # ---------- block handlers ----------

    def _handle_heading(self, tokens: list[Token], i: int) -> int:
        level = int(tokens[i].tag[1])  # 'h1' → 1
        inline = tokens[i + 1]
        markup = render_inline(inline)
        plain = render_inline_plain(inline)

        style_key = f'H{min(level, 4)}'
        self.story.append(Paragraph(markup, self.styles[style_key]))

        # Only top two levels go in the TOC — keeps it scannable.
        if level <= 2:
            self.toc.append((level, plain))
        return i + 3  # heading_open, inline, heading_close

    def _handle_paragraph(self, tokens: list[Token], i: int) -> int:
        inline = tokens[i + 1]
        markup = render_inline(inline)
        if markup.strip():
            self.story.append(Paragraph(markup, self.styles['Body']))
        return i + 3

    def _handle_code_block(self, tokens: list[Token], i: int) -> int:
        text = tokens[i].content.rstrip('\n')
        # Soft-wrap very long lines so we don't blow the right margin.
        wrapped = self._soft_wrap_code(text, max_chars=88)
        self.story.append(Preformatted(wrapped, self.styles['Code']))
        return i + 1

    def _handle_list(self, tokens: list[Token], i: int, ordered: bool) -> int:
        depth = self._list_depth
        self._list_depth += 1
        i += 1  # consume the *_list_open
        item_index = 0
        while i < len(tokens):
            t = tokens[i]
            if t.type in ('bullet_list_close', 'ordered_list_close'):
                i += 1
                break
            if t.type == 'list_item_open':
                item_index += 1
                i = self._handle_list_item(tokens, i, depth, ordered, item_index)
            else:
                i += 1
        self._list_depth -= 1
        return i

    def _handle_list_item(
        self, tokens: list[Token], i: int, depth: int, ordered: bool, idx: int,
    ) -> int:
        i += 1  # consume list_item_open
        # The first paragraph in the item becomes the bullet line. Subsequent
        # paragraphs / nested lists render after, indented to match.
        first_paragraph_consumed = False
        while i < len(tokens):
            t = tokens[i]
            if t.type == 'list_item_close':
                i += 1
                break
            if t.type == 'paragraph_open':
                inline = tokens[i + 1]
                markup = render_inline(inline)
                marker = f'{idx}.' if ordered else '•'
                style = self.styles['BulletNested'] if depth > 0 else self.styles['Bullet']
                if not first_paragraph_consumed:
                    self.story.append(Paragraph(f'{marker} {markup}', style))
                    first_paragraph_consumed = True
                else:
                    # Continuation paragraph inside the same item — indent
                    # to the bullet text position.
                    cont = ParagraphStyle(
                        'Cont', parent=style, leftIndent=style.leftIndent + 6,
                        spaceAfter=4,
                    )
                    self.story.append(Paragraph(markup, cont))
                i += 3  # paragraph_open, inline, paragraph_close
            elif t.type in ('bullet_list_open', 'ordered_list_open'):
                i = self._handle_list(tokens, i, ordered=t.type == 'ordered_list_open')
            elif t.type in ('fence', 'code_block'):
                i = self._handle_code_block(tokens, i)
            else:
                i += 1
        return i

    def _handle_blockquote(self, tokens: list[Token], i: int) -> int:
        i += 1  # consume blockquote_open
        parts: list[str] = []
        while i < len(tokens):
            t = tokens[i]
            if t.type == 'blockquote_close':
                i += 1
                break
            if t.type == 'paragraph_open':
                inline = tokens[i + 1]
                parts.append(render_inline(inline))
                i += 3
            else:
                i += 1
        if parts:
            joined = '<br/><br/>'.join(parts)
            self.story.append(Paragraph(joined, self.styles['Quote']))
        return i

    def _handle_table(self, tokens: list[Token], i: int) -> int:
        # Walk to table_close, collecting [ [cellMarkup, ...], ... ]. Header
        # row is the contents of the thead; body rows are the tbody.
        i += 1  # consume table_open
        header_row: list[str] = []
        body_rows: list[list[str]] = []
        target = None  # 'head' or 'body'
        current_row: list[str] = []

        while i < len(tokens):
            t = tokens[i]
            if t.type == 'table_close':
                i += 1
                break
            if t.type == 'thead_open':
                target = 'head'
            elif t.type == 'tbody_open':
                target = 'body'
            elif t.type == 'tr_open':
                current_row = []
            elif t.type == 'tr_close':
                if target == 'head':
                    header_row = current_row
                else:
                    body_rows.append(current_row)
            elif t.type in ('th_open', 'td_open'):
                # Next token is inline.
                inline = tokens[i + 1]
                current_row.append(render_inline(inline))
                i += 2  # th/td_open + inline
                # Skip until matching close.
                while i < len(tokens) and tokens[i].type not in ('th_close', 'td_close'):
                    i += 1
            i += 1

        if header_row:
            data = [
                [Paragraph(self._table_cell(c), self.styles['Body']) for c in header_row]
            ] + [
                [Paragraph(self._table_cell(c), self.styles['Body']) for c in row]
                for row in body_rows
            ]
            n_cols = len(header_row)
            usable_width = LETTER[0] - 2 * inch  # 1in margins each side
            col_widths = [usable_width / n_cols] * n_cols
            tbl = Table(data, colWidths=col_widths, repeatRows=1)
            tbl.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c5f2d')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9.5),
                ('LEADING', (0, 0), (-1, -1), 13),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('TEXTCOLOR', (0, 1), (-1, -1), colors.HexColor('#1a1a1a')),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1),
                    [colors.white, colors.HexColor('#f4f4f2')]),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ('LINEBELOW', (0, 0), (-1, 0), 0.5, colors.HexColor('#dcdcd5')),
            ]))
            self.story.append(Spacer(1, 0.08 * inch))
            self.story.append(tbl)
            self.story.append(Spacer(1, 0.12 * inch))
        return i

    # ---------- helpers ----------

    @staticmethod
    def _soft_wrap_code(text: str, max_chars: int) -> str:
        """Insert breaks in over-long code lines so they fit the page width.

        Conservative — only wraps lines that would clearly overflow. Tries to
        break on space; otherwise hard-breaks. Used for code blocks which
        Preformatted renders without word-wrap.
        """
        out_lines = []
        for line in text.split('\n'):
            if len(line) <= max_chars:
                out_lines.append(line)
                continue
            remaining = line
            while len(remaining) > max_chars:
                # Try breaking on the last space at-or-before max_chars.
                break_at = remaining.rfind(' ', 0, max_chars)
                if break_at < max_chars * 0.6:  # space too far left → hard break
                    break_at = max_chars
                out_lines.append(remaining[:break_at])
                remaining = '    ' + remaining[break_at:].lstrip()
            out_lines.append(remaining)
        return '\n'.join(out_lines)

    @staticmethod
    def _table_cell(markup: str) -> str:
        """Reportlab Paragraphs in tables can't size from <br/>; flatten."""
        return markup.replace('<br/>', ' ')


# ============ Document orchestration ============

def make_page_template(footer_text: str):
    def draw_footer(canvas, doc):
        canvas.saveState()
        canvas.setFont('Helvetica', 9)
        canvas.setFillColor(colors.HexColor('#6b6b6b'))
        canvas.drawCentredString(
            LETTER[0] / 2, 0.5 * inch,
            f'{footer_text}  ·  Page {doc.page}',
        )
        canvas.restoreState()

    frame = Frame(
        x1=1 * inch, y1=0.85 * inch,
        width=LETTER[0] - 2 * inch,
        height=LETTER[1] - 1.7 * inch,
        showBoundary=0,
    )
    return PageTemplate(id='main', frames=[frame], onPage=draw_footer)


def render_cover(styles, story, subtitle: str, tagline: str) -> None:
    story.append(Spacer(1, 2.4 * inch))
    story.append(Paragraph('Tarn', styles['Title']))
    story.append(Paragraph(subtitle, styles['Subtitle']))
    story.append(Paragraph(tagline, styles['Tagline']))
    story.append(Spacer(1, 1.5 * inch))
    story.append(Paragraph(date.today().strftime('%B %Y'), styles['Date']))
    story.append(PageBreak())


def render_toc(styles, story, toc_entries: Iterable[tuple[int, str]]) -> None:
    story.append(Paragraph('Contents', styles['H1']))
    any_entry = False
    for level, text in toc_entries:
        any_entry = True
        if level == 1:
            story.append(Paragraph(text, styles['TocEntry']))
        else:
            story.append(Paragraph(text, styles['TocSub']))
    if not any_entry:
        story.append(Paragraph('<i>(no headings)</i>', styles['Body']))
    story.append(PageBreak())


def build_pdf(*, source: Path, output: Path, subtitle: str, tagline: str, footer: str) -> None:
    if not source.exists():
        raise FileNotFoundError(f'source markdown not found: {source}')

    md_text = source.read_text(encoding='utf-8')
    md = (
        MarkdownIt('commonmark', {'html': False, 'linkify': True, 'typographer': False})
        .enable('table')
        .enable('strikethrough')
    )
    tokens = md.parse(md_text)

    styles = make_styles()
    walker = Walker(styles)
    walker.walk(tokens)

    output.parent.mkdir(parents=True, exist_ok=True)
    doc = BaseDocTemplate(
        str(output),
        pagesize=LETTER,
        title=f'Tarn — {subtitle}',
        author='Tarn',
        subject=tagline,
        leftMargin=1 * inch, rightMargin=1 * inch,
        topMargin=0.85 * inch, bottomMargin=0.85 * inch,
    )
    doc.addPageTemplates([make_page_template(footer)])

    story: list = []
    render_cover(styles, story, subtitle, tagline)
    render_toc(styles, story, walker.toc)
    story.extend(walker.story)

    doc.build(story)


def main() -> None:
    parser = argparse.ArgumentParser(description='Generate Tarn doc PDFs from markdown.')
    parser.add_argument(
        '--only', nargs='+', choices=[d['name'] for d in DOCS],
        help='Generate only the named PDF(s); default is all.',
    )
    args = parser.parse_args()

    targets = DOCS
    if args.only:
        targets = [d for d in DOCS if d['name'] in set(args.only)]

    for d in targets:
        # Use ASCII arrow — Windows cp1252 console can't encode '→'.
        print(f'[generate-docs-pdf] {d["name"]}: {d["source"].relative_to(REPO_ROOT)} -> {d["output"].relative_to(REPO_ROOT)}')
        build_pdf(
            source=d['source'],
            output=d['output'],
            subtitle=d['subtitle'],
            tagline=d['tagline'],
            footer=d['footer'],
        )
    print(f'[generate-docs-pdf] wrote {len(targets)} PDF(s)')


if __name__ == '__main__':
    main()
