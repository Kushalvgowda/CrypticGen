"""
Command-line interface for CrypticGen password generator.
"""
import argparse
import sys
from .core import CrypticGen


def main():
    """
    Main entry point for the CLI.
    """
    parser = argparse.ArgumentParser(
        description="PassKey: Generate secure passwords and tokens"
    )
    
    # Basic options
    parser.add_argument(
        "-l", "--length", 
        type=int, 
        default=4, 
        help="Password length (default: 4)"
    )
    parser.add_argument(
        "-n", "--number", 
        type=int, 
        default=1, 
        help="Number of passwords to generate (default: 1)"
    )
    
    # Character set options
    char_group = parser.add_argument_group("Character Options")
    char_group.add_argument(
        "--no-uppercase", 
        action="store_false", 
        dest="uppercase", 
        help="Exclude uppercase letters"
    )
    char_group.add_argument(
        "--no-lowercase", 
        action="store_false", 
        dest="lowercase", 
        help="Exclude lowercase letters"
    )
    char_group.add_argument(
        "--no-digits", 
        action="store_false", 
        dest="digits", 
        help="Exclude digits"
    )
    char_group.add_argument(
        "--no-symbols", 
        action="store_false", 
        dest="symbols", 
        help="Exclude symbols"
    )
    char_group.add_argument(
        "-e", "--exclude", 
        type=str, 
        default="", 
        help="Exclude specified characters"
    )
    char_group.add_argument(
        "-c", "--custom", 
        type=str, 
        default="", 
        help="Custom characters to include in the password"
    )
    
    # Output format options
    format_group = parser.add_argument_group("Output Format")
    format_group.add_argument(
        "--hash", 
        action="store_true", 
        help="Output SHA-256 hash of password"
    )
    format_group.add_argument(
        "--url-safe", 
        action="store_true", 
        help="Generate URL-safe token"
    )
    format_group.add_argument(
        "--no-strength", 
        action="store_true", 
        help="Don't display password strength"
    )
    
    # Storage options
    storage_group = parser.add_argument_group("Storage Options")
    storage_group.add_argument(
        "--list", 
        action="store_true", 
        help="List all stored passwords"
    )
    storage_group.add_argument(
        "--delete", 
        type=int, 
        help="Delete password with the specified ID"
    )
    
    args = parser.parse_args()
    
    try:
        # Handle storage operations
        if args.list:
            list_stored_passwords()
            return
            
        if args.delete is not None:
            delete_password(args.delete)
            return
            
        # Initialize PassKey with CLI arguments
        passkey = CrypticGen(
            length=args.length,
            include_uppercase=args.uppercase,
            include_lowercase=args.lowercase,
            include_digits=args.digits,
            include_symbols=args.symbols,
            exclude_char=args.exclude,
            custom_chars=args.custom,
            hash_format=args.hash,
            url_safe=args.url_safe
        )
        
        # Generate passwords
        if args.number > 1:
            passwords = passkey.bulk_generate(args.number).split(',\n')
            for i, password in enumerate(passwords, 1):
                print(f"Password {i}: {password}")
        else:
            password = passkey.generate()
            print(f"Generated password: {password}")
            
            # Show strength if applicable
            if not args.hash and not args.url_safe and not args.no_strength:
                try:
                    strength = passkey.password_strength()
                    print(f"Password strength: {strength}")
                except (TypeError, ValueError):
                    # Skip strength display if there's an error
                    pass
    
    except (ValueError, TypeError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    
    return 0


def list_stored_passwords():
    """List all passwords stored in the password file."""
    try:
        # Create a temporary PassKey object just to access storage
        passkey = CrypticGen(length=12)
        passwords = passkey.get_stored_passwords()
        
        if not passwords:
            print("No stored passwords found.")
            return
            
        print("Stored passwords:")
        print("----------------")
        for id_str, password in passwords.items():
            print(f"ID: {id_str}, Password: {password}")
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)


def delete_password(password_id):
    """Delete a password by ID."""
    try:
        # Create a temporary PassKey object just to access storage
        passkey = CrypticGen(length=12)
        if passkey.delete_password(password_id):
            print(f"Password with ID {password_id} deleted successfully.")
        else:
            print(f"No password found with ID {password_id}.")
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())