import string
import secrets
import hashlib
import json
import re
import random
import requests
from pathlib import Path
from typing import Dict, List, Optional, Union


class CrypticGen:
    """
    A comprehensive password generation and management class.
    
    This class provides functionality for generating secure passwords, evaluating password strength,
    storing passwords, verifying password hashes, generating secure bulk passwords and highly customizable passwords.
    """
    
    def __init__(self, length: int=4, include_uppercase: bool = True, include_lowercase: bool = True, 
                 include_digits: bool = True, include_symbols: bool = True, exclude_char: str = '', 
                 custom_chars: str = '', hash_format: bool = False, url_safe: bool = False, default_exclude: str = r"[\\,\'\"\.`1I|]"):
        """
        Initialize a PassKey instance with password generation configuration.
        
        Args:
            length (int): Length of the password.(default = 4)
            include_uppercase (bool): Include uppercase letters (A-Z).
            include_lowercase (bool): Include lowercase letters (a-z).
            include_digits (bool): Include digits (0-9).
            include_symbols (bool): Include symbols (punctuation).
            exclude_char (str): Characters to exclude from the password.
            custom_chars (str): Custom characters to include in the password.
            hash_format (bool): If True, return hashed password (SHA-256).
            url_safe (bool): If True, generate URL-safe token.
            default_exclusion (str): Automatically excludes the confusing characters.(can be customized by the user or leave it default)
        
        Raises:
            ValueError: If length < 3, less than 3 character set is selected, or character set is less than 3 after exclusions.
        """
        if not isinstance(length, int):
            raise TypeError("Length must be an integer")
            
        if length < 3:
            raise ValueError("Password length must be at least 3 characters")
        
        self.length = length
        self.include_uppercase = include_uppercase
        self.include_lowercase = include_lowercase
        self.include_digits = include_digits
        self.include_symbols = include_symbols
        self.exclude_char = exclude_char
        self.custom_chars = custom_chars
        self.hash_format = hash_format
        self.url_safe = url_safe
        self.default_exclude = default_exclude
        self.key = None  # Generated password or token
        self.og = None   # Original password before hashing (if applicable)
        
        # Build the character set based on configuration

        
        # Path to the passwords storage file
        self.file = Path("passwords.json")
    
        """
        Build the character set based on configuration.
        
        Returns:
            str: The character set to use for password generation.
            
        Raises:
            ValueError: If no character sets are selected or all characters are excluded.
        """
        self.char_set = ''
        
        if self.include_uppercase:
            self.char_set += string.ascii_uppercase
        if self.include_lowercase:
            self.char_set += string.ascii_lowercase
        if self.include_digits:
            self.char_set += string.digits
        if self.include_symbols:
            self.char_set += string.punctuation
        if self.custom_chars:
            self.char_set += self.custom_chars

        self.char_set = ''.join(c for c in self.char_set if c not in self.default_exclude)
        
        if not self.char_set:
            raise ValueError("At least one character set or custom characters must be included")
        
        if self.exclude_char:
            self.char_set = ''.join(c for c in self.char_set if c not in self.exclude_char)
        
        if not self.char_set:
            raise ValueError("Character set is empty after excluding characters")
        
       
        
    def _load_passwords(self) -> Dict:
        """
        Load passwords from the storage file.
        
        Returns:
            Dict: A dictionary containing the next ID and all stored passwords.
            
        Raises:
            ValueError: If there's an error reading or parsing the file.
        """
        if not self.file.exists() or self.file.stat().st_size == 0:
            return {"next_id": 1, "passwords": {}}
        
        try:
            with open(self.file, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Error decoding passwords.json: {e}")
        except IOError as e:
            raise ValueError(f"Error reading passwords.json: {e}")

    def _save_passwords(self, data: Dict) -> None:
        """
        Save passwords to the storage file.
        
        Args:
            data (Dict): The password data to save.
            
        Raises:
            ValueError: If there's an error writing to the file.
        """
        try:
            with open(self.file, 'w') as f:
                json.dump(data, f, indent=2)
        except IOError as e:
            raise ValueError(f"Error writing to passwords.json: {e}")
    
    def get_stored_passwords(self) -> Dict:
        """
        Retrieve all stored passwords.
        
        Returns:
            Dict: Dictionary with password IDs as keys and passwords as values.
        """
        data = self._load_passwords()
        return data["passwords"]
    
    def delete_password(self, password_id: int) -> bool:
        """
        Delete a password by ID.
        
        Args:
            password_id (int): The ID of the password to delete.
            
        Returns:
            bool: True if password was deleted, False if not found.
            
        Raises:
            ValueError: If there's an error reading or writing the passwords file.
        """
        data = self._load_passwords()
        
        # Convert string keys to integers for comparison
        password_id_str = str(password_id)
        if password_id_str in data["passwords"]:
            del data["passwords"][password_id_str]
            self._save_passwords(data)
            return True
        return False
        
    def generate(self) -> str:
        """
        Generate a unique password or token and store it in 'passwords.json' file.
        Regenerates if the password already exists in the file.
        
        Returns:
            str: The generated password, hashed password, or URL-safe token.
        
        Raises:
            ValueError: If unable to read/write passwords.json or if too many attempts fail to generate a unique password.
        """
        # Load existing passwords
        data = self._load_passwords()
        passwords_list = data["passwords"]
        max_attempts = 100  # Prevent infinite loops
        

        for _ in range(max_attempts):
            # Generate password or token
            if self.url_safe:
                self.og = secrets.token_urlsafe(self.length)
            else:
                self.og = ''.join(secrets.choice(self.char_set) for _ in range(self.length))
            
            self.key = self.og
            
            if self.hash_format:
                self.key = hashlib.sha256(self.og.encode()).hexdigest()
            
            # Check for duplicates
            if self.key not in passwords_list.values():
                # Store password with next available ID
                password_id = data["next_id"]
                passwords_list[password_id] = self.key
                data["next_id"] += 1
                self._save_passwords(data)
                return self.key
        
        raise ValueError("Could not generate a unique password after maximum attempts")
    
    def verify(self, password: str) -> bool:
        """
        Verify a password against the currently generated password.
        
        Args:
            password (str): The password to verify.
            
        Returns:
            bool: True if the password matches, False otherwise.
            
        Raises:
            ValueError: If no password has been generated yet.
        """
        if self.og is None:
            raise ValueError("No password has been generated to verify against")
        
        if self.hash_format:
            # Verify against the SHA-256 hash of the original password
            expected_hash = hashlib.sha256(self.og.encode()).hexdigest()
            return password == expected_hash
        else:
            # Verify against the original password or URL-safe token
            return password == self.og
            
    def password_strength(self, password: Optional[str] = None) -> Union[str, Dict[str, str]]:
        """
        Evaluate the strength of a password. Password can be class generated or other random password
        
        Args:
            password (str, optional): The password to evaluate. If None, evaluates the last generated password.
            
        Returns:
            Union[str, Dict[str, str]]: 
                - For single passwords: "WEAK", "MODERATE", or "STRONG"
                - For multi-word passwords: A dictionary mapping each word to its strength
                
        Raises:
            ValueError: If no password is provided and none has been generated.
            TypeError: If password strength checking is attempted on a hashed or URL-safe password.
        """
        if self.hash_format:
            raise TypeError("Hashed password is not eligible for strength check")
        if self.url_safe:
            raise TypeError("URL-safe password is not eligible for strength check")
        
        if password is None:
            if self.key is None:
                raise ValueError("No password has been generated or given to evaluate")
            password = self.key

        if not isinstance(password, str):
            raise ValueError("Password must be a string")
        if not password:
            raise ValueError("Password cannot be empty")
        
        # Check if it's a multi-word password
        words = password.split()
        if len(words) > 1:
            result = {}
            for word in words:
                result[word] = self._evaluate_password_strength(word)
            return result
        else:
            return self._evaluate_password_strength(password)
    
    def _evaluate_password_strength(self, password: str) -> str:
        """
        Helper method to evaluate the strength of a single password.
        
        Args:
            password (str): The password to evaluate.
            
        Returns:
            str: "WEAK", "MODERATE", or "STRONG"
        """
        score = 0
        
        if len(password) >= 8:
            score += 1
            
        # Character type criteria
        if any(char.islower() for char in password):
            score += 1
        if any(char.isupper() for char in password):
            score += 1
        if any(char.isdigit() for char in password):
            score += 1
        if any(char in string.punctuation for char in password):
            score += 1
            
        # Check for common patterns that weaken passwords
        if re.search(r'12345|qwerty|password|admin|welcome', password.lower()):
            score -= 1
            
        # Sequential characters reduce score
        for i in range(len(password) - 2):
            if (ord(password[i+1]) == ord(password[i]) + 1 and 
                ord(password[i+2]) == ord(password[i]) + 2):
                score -= 1
                break
                
        # Repeated characters reduce score
        if re.search(r'(.)\1{2,}', password):
            score -= 1
            
        # Determine strength based on adjusted score
        if score <= 2:
            return "WEAK"
        elif score <= 4:
            return "MODERATE"
        else:
            return "STRONG"
        
    def bulk_generate(self, number_passwords: int) -> str:
        """
        Generate multiple unique passwords.
        
        Args:
            number_passwords (int): Number of passwords to generate.
            
        Returns:
            str: Comma-separated string of generated passwords.
            
        Raises:
            ValueError: If number_passwords is not a positive integer.
        """
        if not isinstance(number_passwords, int):
            raise TypeError("Number of passwords must be an integer")
        if number_passwords <= 0:
            raise ValueError("Number of passwords must be positive")
        
        passwords = []
        for _ in range(number_passwords):
            password = self.generate()  # Reuse existing generate method
            passwords.append(password)  # append the generated passwords to passwords list
        return ',\n'.join(passwords)    # returns the passwords in string format
    
    def encrypytion(self,password: str) -> str:
        """
        Generate encrypted message for given string.
        
        Args:
            password (str): password for encryption.
            
        Returns:
            str: Encrypted password.
            
        Raises:
            TypeError: If password is not a string.
            ValueError: If password is empty

        """
        if not password:
            raise ValueError("Password must not be empty")
        if not isinstance(password, str):
            raise TypeError("Password must be string")

        self.chars = self.char_set+self.default_exclude+" "  # Adds all character sets including whitespaces
        self.chars = list(self.chars)       # Converts them to list for looping
        self.vault = self.chars.copy()     # Copying for index matching

        random.shuffle(self.vault)         # Shuffling the copied list

        encrypted_string = ""
        for char in password:
            index = self.chars.index(char)     # Pick the charcater index of the given password
            encrypted_string+=self.vault[index]  # Matches the index with shuffled list and add to encrpted_string
        return encrypted_string
    
    def decryption(self,password: str) -> str:
        """
        Generates decrypted message for encrypted password

        """
        if not password:
            raise ValueError("Password must not be empty")
        if not isinstance(password, str):
            raise TypeError("Password must be string")
        
        decrypted_string = ""
        for char in password:
            index = self.vault.index(char)
            decrypted_string+=self.chars[index]
        return decrypted_string
    

    def password_breach(self, password: str) -> str:
        """
        Checks if a password has been compromised using the API of secure k-Anonymity method (Have I Been Pwned).

        Args:
            password (str): password for checking breaching.
        
        Returns:
            - If network/API errooccurred, return a string.(-1)
            - If count>0, returns string with number of count in it.(int(count>0))
            - If no breach, then return string. (int(count=0))

        Raises:
            TypeError: If password is not a string.
            ValueError: If password is empty

        Security of passwords: (HIBP) uses k-Anonymity method for security. 
        This module sends sha-1 hashed of the password with only 5 characters.
        Please read the Package documentation for further security and safety taken.

        Note: HIBP shows breach of a password only if it was added to list of HIBP breaches. So, it's always
        good practice to change the password oftenly.
        Use crypticgen module to generate highly customisable, secure & cryptographic passwords.
        """
        if not password:
            raise ValueError("Password must not be empty")
        if not isinstance(password, str):
            raise TypeError("Password must be string")
        
        sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]

        url = f"https://api.pwnedpasswords.com/range/{prefix}"

        try:
            response = requests.get(url, timeout=5)
            response.raise_for_status()
        except requests.RequestException:
            print("Could not check the password (network error).")
            return -1
            
        for line in response.text.splitlines():
            hash_suffix, count = line.split(":")
            if hash_suffix == suffix:
                return f"⚠️ Password has been found {int(count)} times in data breaches. Consider changing it.\n Use crypticgen module to generate secure passwords"

        return f"✅ Password not found in known breaches. If you are worried about your password,\nUse crypticgen module to generate secure passwords"

