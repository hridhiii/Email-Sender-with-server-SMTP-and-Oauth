"""Email HTML preparation utilities.

Preserves:
- Global font family + font size.
- Global default paragraph gap.
- Local per-paragraph gap overrides via [gap:N], [gap:reset].
- Bullet list styling.
"""

import re


class SafeDict(dict):
    """format_map-safe dict that leaves unknown placeholders untouched."""
    def __missing__(self, key: str) -> str:
        return "{" + key + "}"



def build_common_inline_style(font_stack: str, font_size_px: int) -> str:
    return (
        f"font-family:{font_stack}; "
        f"font-size:{int(font_size_px)}px; "
        "line-height:1.4; "
        "color:#000000;"
    )


def _strip_tags(html_fragment: str) -> str:
    return re.sub(r"(?is)<[^>]*>", "", html_fragment)


def _style_paragraph_block(block_html: str, gap_px: int, common_style: str) -> str:
    m = re.match(r"(?is)<p[^>]*>(.*?)</p>", block_html)
    inner_html = m.group(1) if m else block_html
    return (
        f'<p style="{common_style} margin:0 0 {gap_px}px 0;">'
        f"{inner_html}</p>"
    )


def _style_ul_block(block_html: str, gap_px: int, common_style: str) -> str:
    m = re.match(r"(?is)<ul[^>]*>(.*?)</ul>", block_html)
    inner_html = m.group(1) if m else block_html
    li_gap = max(1, int(gap_px // 2))

    def _style_li(m2):
        li_inner = m2.group(1)
        return (
            f'<li style="{common_style} margin:0 0 {li_gap}px 0;">'
            f"{li_inner}</li>"
        )

    inner_html2 = re.sub(
        r"(?is)<li[^>]*>(.*?)</li>",
        _style_li,
        inner_html,
    )

    return (
        '<ul style="'
        f'margin:0 0 {gap_px}px 24px; '
        'padding:0; '
        'list-style-position:outside;'
        '">'
        f"{inner_html2}</ul>"
    )


def prepare_email_html(raw_html: str, default_gap_px: int, font_stack: str, font_size_px: int) -> str:
    """Render sanitized HTML honoring [gap:*] directives and global font/spacing.

    The Quill editor content is treated as HTML and transformed to:
    - apply a consistent font + size
    - normalize paragraph and bullet spacing
    - support local [gap:N] and [gap:reset] commands as standalone paragraphs
    """
    html = str(raw_html or "")
    common_style = build_common_inline_style(font_stack, font_size_px)

    token_pattern = re.compile(
        r"(?is)(<p[^>]*>.*?</p>|<ul[^>]*>.*?</ul>|<br\s*/?>)"
    )
    blocks = token_pattern.findall(html)

    current_gap = int(default_gap_px)
    rendered_blocks = []

    for block in blocks:
        tag_match = re.match(r"(?is)<\s*([a-z0-9]+)", block)
        if not tag_match:
            continue
        tagname = tag_match.group(1).lower()

        if tagname == "p":
            inner_text = _strip_tags(block).strip()
            m_gap_num = re.match(r"^\[gap\s*:\s*([0-9]+)\]$", inner_text, flags=re.I)
            m_gap_reset = re.match(r"^\[gap\s*:\s*(reset|normal)\]$", inner_text, flags=re.I)

            if m_gap_num:
                current_gap = int(m_gap_num.group(1))
                continue
            elif m_gap_reset:
                current_gap = int(default_gap_px)
                continue
            else:
                rendered_blocks.append(_style_paragraph_block(block, current_gap, common_style))

        elif tagname == "ul":
            rendered_blocks.append(_style_ul_block(block, current_gap, common_style))

        elif tagname == "br":
            rendered_blocks.append("<br/>")

        else:
            rendered_blocks.append(block)

    final_html = (
        f'<div style="{common_style} white-space:normal;">'
        f"<!--rendered-by-bulk-outreach-->" + "".join(rendered_blocks) + "</div>"
    )
    return final_html


def font_stack_from_key(key: str) -> str:
    fallback_map = {
        "Verdana": "Verdana, Arial, sans-serif",
        "Arial": "Arial, Helvetica, sans-serif",
        "Tahoma": "Tahoma, Verdana, sans-serif",
        "Helvetica": "Helvetica, Arial, sans-serif",
        "Times New Roman": '"Times New Roman", Times, serif',
        "Georgia": 'Georgia, "Times New Roman", serif',
        "Courier New": '"Courier New", Courier, monospace',
    }
    return fallback_map.get(key or "Verdana", "Verdana, Arial, sans-serif")
