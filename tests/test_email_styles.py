from app.email_styles import prepare_email_html, font_stack_from_key

def test_gap_directives():
    html = "<p>Hello</p><p>[gap:20]</p><p>World</p>"
    out = prepare_email_html(html, 6, font_stack_from_key("Verdana"), 13)
    assert "Hello" in out and "World" in out
    assert "margin:0 0 20px 0" in out

def test_font_stack():
    assert "Verdana" in font_stack_from_key("Verdana")
