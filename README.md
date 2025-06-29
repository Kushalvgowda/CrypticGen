# CrypticGen 🔐

***CrypticGen*** is a powerful, secure and customisable password generation and management utility for Python.

## Features

- Generate strong, cryptographically secure passwords
- Customize character sets (uppercase, lowercase, digits, symbols)
- Inclsion & Exclusion of characters
- Default exclusion of confusing characters (customizable)
- Evaluate password strength
- Generate URL-safe tokens
- Output SHA-256 hashed passwords
- Store and retrieve generated passwords
- Command-line interface for easy use
- Encrypt & Decrypt the password
- Check for password breach through k-Anonymity method (HIBP)

## Technologies used

- Python, Pytest, HIBP API, PyPi, Git

## Installation

```bash
pip install crypticgen
```

## Command Line Usage

### Basic Usage

```bash
# Generate a default 04-character password
crypticgen

# Generate a 16-character password
crypticgen --length 16
```

### Character Set Options

```bash
# No symbols
crypticgen --no-symbols

# Excxludes lowercase & symbols from password
crypticgen --no-lowercase --no-symbols

# Exclude specified characters
crypticgen --exclude "0O1Il"

# Add custom characters
crypticgen --custom "!@#$%"
```

### Multiple Passwords

```bash
# Generate 5 passwords
crypticgen --number 5
```

### Output Formats

```bash
# Generate hashed password (SHA-256)
crypticgen --hash

# Generate URL-safe token
crypticgen --url-safe

# Don't show password strength
crypticgen --no-strength
```

### Managing Stored Passwords

```bash
# List all stored passwords
crypticgen --list

# Delete a password by ID
crypticgen --delete 3
```


### Python API Usage ###

```python
from crypticgen import CrypticGen

# Create a PassKey instance
pk = CrypticGen(
    length=16,
    include_uppercase=True,  # includes uppercase characters if True
    include_lowercase=True,  # includes lowercase characters if True
    include_digits=True,    # includes digits if True
    include_symbols=True,   # includes symbols if True
    exclude_char="0O1Il",  # Exclude specified characters if mentioned
    custom_chars="",    # Add custom characters if mentioned
    hash_format=False,  # Output SHA-256 hash if True
    url_safe=False,     # Generate URL-safe token if True
    default_exclude = r"[\\,\'\"\.`1I|]"   # excludes confusing characters by default. Can be customisable  
)

# Generate a password
password = pk.generate()
print(f"Generated password: {password}")

# Check password strength
strength = pk.password_strength(password)
print(f"Password strength: {strength}")

# Generate multiple passwords
multiple_passwords = pk.bulk_generate(5)
print(multiple_passwords)

# Verify a password
if pk.verify(password):
    print("Password verified!")


# Password Breach Checker through HIBP API
check = pk.password_breach(password)
print(check)
## 🔑 Password Breach Check (Have I Been Pwned Integration) ##
crypticgen uses the official [Have I Been Pwned](https://haveibeenpwned.com/) API (https://api.pwnedpasswords.com/range/{first 5 hash chars}) to safely and securely check if a password has appeared in known data breaches.
This feature uses the [k-Anonymity model](https://en.wikipedia.org/wiki/K-anonymity), meaning your full password or full hash is **never sent over the internet**, ensuring maximum privacy and safety.
> Data provided by Have I Been Pwned (https://haveibeenpwned.com/), a service by Troy Hunt.


# Password encryption & decryption
encrypted = pk.encryption(password)
print(encrypted)
decrypted = pk.decrypted(encrypted)
print(decrypted)


```

## License

MIT License

Copyright (c) [2025] [Kushal V]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
