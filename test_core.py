"""
Pytest for CrypticGen package
"""

import pytest
from crypticgen.core import CrypticGen


def test_generate():
    pk = CrypticGen(length=10)
    password = pk.generate()
    assert isinstance(password, str)
    assert len(password) == 10
    assert all(char in pk.char_set for char in pk.key)

def test_generate_hashed_password():
    pk = CrypticGen(length=10, hash_format=True)
    password = pk.generate()
    assert len(password) == 64  
    assert pk.og is not None
    assert pk.key == password

def test_generate_url_safe():
    pk = CrypticGen(length=10, url_safe=True)
    password = pk.generate()
    assert isinstance(password, str)
    assert pk.og == password
    assert pk.url_safe is True

def test_password_uniqueness():
    pk1 = CrypticGen(length=8)
    pk2 = CrypticGen(length=8)
    pw1 = pk1.generate()
    pw2 = pk2.generate()
    assert pw1 != pw2

def test_verify_hashed_password():
    pk = CrypticGen(length=10, hash_format=True)
    hashed = pk.generate()
    assert pk.verify(hashed)

def test_verify_plain_password():
    pk = CrypticGen(length=10)
    original = pk.generate()
    assert pk.verify(original)

def test_strength():
    pk = CrypticGen(length=8)
    pw = pk.generate()
    assert pk.password_strength("password") == "WEAK"
    assert pk.password_strength("Abcd1234") == "MODERATE"
    assert pk.password_strength("A$tr0ng!Pwd") == "STRONG"
    assert pk.password_strength(pw) in ["WEAK","MODERATE","STRONG"]

def test_strength_multiword():
    pk = CrypticGen()
    result = pk.password_strength("admin qwerty A$tr0ng!Pwd")
    assert isinstance(result, dict)
    assert result["admin"] == "WEAK"
    assert result["qwerty"] == "WEAK"
    assert result["A$tr0ng!Pwd"] == "STRONG"

def test_bulk_generate():
    pk = CrypticGen()
    results = pk.bulk_generate(5)
    assert len(results.split()) == 5

def test_encryption():
    pk = CrypticGen()
    results = pk.encrypytion("sample_password")
    assert len(results) == len("sample_password")

def test_decryption():
    pk = CrypticGen()
    x = pk.encrypytion("sample_password")
    results = pk.decryption(x)
    assert "sample_password" == results
    assert len(results) == len("sample_password")

def test_breach():
    pk = CrypticGen()
    x = pk.password_breach("123_password")
    assert (
        x == "Could not check the password (network error)."
        or "⚠️ Password has been found" in x
        or "✅ Password not found in known breaches." in x
    )

def test_invalid_config_raises():
    with pytest.raises(ValueError):
        CrypticGen(length=2)

    with pytest.raises(ValueError):
        CrypticGen(length=8, include_uppercase=False, include_lowercase=False,
                include_digits=False, include_symbols=False)

def test_exclude_chars():
    pk = CrypticGen(length=10, exclude_char="abcABC123")
    pk.generate()
    assert all(c not in "abcABC123" for c in pk.og)

def test_empty_char_set_error():
    with pytest.raises(ValueError):
        CrypticGen(length=8, include_uppercase=False, include_lowercase=False,
                include_digits=False, include_symbols=False, custom_chars="").generate()
        
