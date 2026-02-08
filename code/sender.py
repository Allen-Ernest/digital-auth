from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# -----------------------------
# Generate RSA Keys
# -----------------------------
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

public_key = private_key.public_key()

# -----------------------------
# Save Private Key
# -----------------------------
with open("private_key.pem", "wb") as f:
    f.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

# -----------------------------
# Save Public Key
# -----------------------------
with open("public_key.pem", "wb") as f:
    f.write(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

print("Keys generated and saved successfully.")

# -----------------------------
# Message Input
# -----------------------------
message = input("Enter message to send: ")

# -----------------------------
# Sign Message
# -----------------------------
signature = private_key.sign(
    message.encode(),
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# -----------------------------
# Save Message and Signature
# -----------------------------
with open("message.txt", "w") as f:
    f.write(message)

with open("signature.bin", "wb") as f:
    f.write(signature)

print("Message signed and sent.")
