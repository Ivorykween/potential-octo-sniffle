# potential-octo-sniffle
I developed a Python-based password strength checker to evaluate password security based on complexity rules such as length, character diversity, and entropy. As an optional feature, I integrated breach detection using the Have I Been Pwned API, allowing users to verify if their passwords had been exposed in known data breaches. 
import re
import hashlib
import requests # type: ignore 

HIBP_API_URL = "https://api.pwnedpasswords.com/range/"

def check_password_strength(password):
    # Define password complexity requirements
    min_length = 8
    has_upper = bool(re.search(r"[A-Z]", password))
    has_lower = bool(re.search(r"[a-z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_special = bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password))
    
    # Check password length
    if len(password) < min_length:
        return "Weak: Password must be at least 8 characters long."
    
    # Count complexity factors
    complexity = sum([has_upper, has_lower, has_digit, has_special])
    
    # Determine password strength
    if complexity == 4:
        strength = "Strong: Password meets all security requirements."
    elif complexity == 3:
        strength = "Moderate: Consider adding more complexity."
    else:
        strength = "Weak: Password is too simple, add uppercase, lowercase, digits, and special characters."
    
    # Check if the password has been breached
    if is_password_pwned(password):
        strength += " ⚠️ WARNING: This password has been found in a data breach. Choose a different one!"
    
    return strength

def is_password_pwned(password):
    """Check if the password is in a data breach using Have I Been Pwned API."""
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]

    response = requests.get(HIBP_API_URL + prefix)
    if response.status_code != 200:
        print("Error checking password breach status.")
        return False

    hashes = (line.split(":") for line in response.text.splitlines())
    return any(suffix == hash_suffix for hash_suffix, _ in hashes)

# Example usage
if __name__ == "__main__":
    password = input("Enter your password: ")
    result = check_password_strength(password)
    print(result)
