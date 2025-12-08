import secrets
import string

def generate_random_password(length=12):
    
    letters = string.ascii_letters      
    digits = string.digits             
    symbols = "!@#$%^&*()"

    all_chars = letters + digits + symbols

   
    password = ''.join(secrets.choice(all_chars) for _ in range(length))

    return password
