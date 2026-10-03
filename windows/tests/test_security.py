from pathlib import Path
import pytest, security

@pytest.mark.parametrize("bad,expected", [
    ("../../Windows/System32/file", "file"), ("..\\..\\evil.exe", "evil.exe"), ("a/b/c.txt", "c.txt"),
    ("CON", "_CON"), ("na:me?.txt", "na_me_.txt"), ("", "file"), ("...", "file"), ("évil файл 文件.pdf", "évil файл 文件.pdf")])
def test_sanitize(bad, expected): assert security.sanitize_filename(bad) == expected

def test_long_name_keeps_extension():
    n = security.sanitize_filename("a" * 400 + ".pdf"); assert len(n) <= 150 and n.endswith(".pdf")

def test_unique_path(tmp_path):
    (tmp_path / "d.pdf").write_text("x")
    assert security.unique_path(tmp_path, "d.pdf").name == "d (1).pdf"
    (tmp_path / "d (1).pdf").write_text("x")
    assert security.unique_path(tmp_path, "d.pdf").name == "d (2).pdf"

def test_ensure_inside(tmp_path):
    with pytest.raises(ValueError): security.ensure_inside(tmp_path, tmp_path / ".." / "x")

def test_pin_is_random_6_digits():
    pins = {security.new_pin() for _ in range(50)}
    assert all(len(p) == 6 and p.isdigit() for p in pins) and len(pins) > 40
