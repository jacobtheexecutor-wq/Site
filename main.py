import random

def generate_random_string(length=32):
    """Generate a random string of specified length."""
    characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return ''.join(random.choice(characters) for _ in range(length))

generated_secret = generate_random_string(64)
print(f"Generated SESSION_SECRET: {generated_secret}")