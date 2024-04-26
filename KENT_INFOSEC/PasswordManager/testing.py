import re

def check_password_strength(password):
    # Check for the length of the password
    if len(password) < 8:
        return "Weak", "Password too short (minimum 8 characters)."
    
    # Check for the presence of lowercase and uppercase letters
    if not re.search(r"[a-z]", password) or not re.search(r"[A-Z]", password):
        return "Weak", "Password must contain both lowercase and uppercase letters."
    
    # Check for the presence of digits
    if not re.search(r"[0-9]", password):
        return "Weak", "Password must contain numbers."
    
    # Check for the presence of special characters
    # Include the '[' character in the character class
    if not re.search(r"[!@#$%^&*()_+{}\[\]:;\"'|<>,.?/~`-]", password):
        return "Medium", "Add special characters for a stronger password."
    
    if len(password) >= 12:
        return "Strong", "Strong password."
    else:
        return "Medium", "Password should be at least 12 characters long for extra strength."

# Test the function
strength, message = check_password_strength("dj7a90jq[keJ")
print(strength, message)  # Should recognize as a stronger password now