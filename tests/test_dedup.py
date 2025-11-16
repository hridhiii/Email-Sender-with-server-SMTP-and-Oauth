from app.security import encrypt_secret, decrypt_secret, hash_email, load_sent_hashes, record_sent_hash
from app.security import normalize_email
import os
from pathlib import Path

def test_encrypt_roundtrip():
    secret = "super-secret"
    token = encrypt_secret(secret)
    assert decrypt_secret(token) == secret

def test_hash_and_record(tmp_path, monkeypatch):
    # redirect SENT_INDEX_DIR
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    from importlib import reload
    import app.security as sec
    reload(sec)

    h1 = sec.hash_email("Test@Email.com")
    h2 = sec.hash_email("test@email.com")
    assert h1 == h2

    sec.record_sent_hash("sender@example.com", "test@email.com", "m1", "job1")
    hashes = sec.load_sent_hashes("sender@example.com")
    assert sec.hash_email("test@email.com") in hashes

def test_normalize_email():
    assert normalize_email("  A@B.Com ") == "a@b.com"
