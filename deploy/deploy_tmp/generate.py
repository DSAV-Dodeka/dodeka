import secrets
import base64

# Generate a 32-byte secret using the secrets module
secret = secrets.token_bytes(32)

# Encode the secret in base64url
base64url_secret = base64.urlsafe_b64encode(secret).decode('utf-8').rstrip('=')

# Print the base64url-encoded secret
print(base64url_secret)