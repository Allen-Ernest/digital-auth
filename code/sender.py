import customtkinter as ctk
import logging
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Logging Handler for GUI

class GUILogHandler(logging.Handler):
    def __init__(self, textbox):
        super().__init__()
        self.textbox = textbox

    def emit(self, record):
        msg = self.format(record)
        self.textbox.configure(state="normal")
        self.textbox.insert("end", msg + "\n")
        self.textbox.configure(state="disabled")
        self.textbox.see("end")


# Sender Application

class SenderApp(ctk.CTk):

    def __init__(self):
        super().__init__()

        self.title("Secure Sender - Digital Signature & Encryption")
        self.geometry("900x600")

        ctk.set_appearance_mode("dark")

        # UI Layout
        self.message_entry = ctk.CTkTextbox(self, height=100)
        self.message_entry.pack(padx=10, pady=10, fill="x")

        self.send_btn = ctk.CTkButton(self, text="Encrypt & Sign Message", command=self.process_message)
        self.send_btn.pack(pady=10)

        self.toggle_pub = ctk.CTkButton(self, text="Toggle Public Key", command=self.toggle_public)
        self.toggle_pub.pack(pady=5)

        self.toggle_cipher = ctk.CTkButton(self, text="Toggle Ciphertext", command=self.toggle_cipher)
        self.toggle_cipher.pack(pady=5)

        self.log_box = ctk.CTkTextbox(self)
        self.log_box.pack(padx=10, pady=10, fill="both", expand=True)
        self.log_box.configure(state="disabled")

        self.hidden = True
        self.public_key_text = ""
        self.cipher_text = ""

        # Logging
        self.logger = logging.getLogger("SENDER_GUI")
        self.logger.setLevel(logging.INFO)

        handler = GUILogHandler(self.log_box)
        handler.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))
        self.logger.addHandler(handler)

    # -----------------------------
    def process_message(self):
        self.logger.info("Sender started.")

        # Key generation
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        with open("private_key.pem", "wb") as f:
            f.write(private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()
            ))

        with open("public_key.pem", "wb") as f:
            f.write(public_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        self.public_key_text = public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        self.logger.info("RSA keys generated.")

        # Message
        message = self.message_entry.get("1.0", "end").strip().encode()
        self.logger.info("Message received from GUI.")

        # AES
        aes_key = os.urandom(32)
        iv = os.urandom(16)

        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_message = iv + encryptor.update(message) + encryptor.finalize()

        with open("encrypted_message.bin", "wb") as f:
            f.write(encrypted_message)

        self.cipher_text = encrypted_message.hex()
        self.logger.info("Message encrypted using AES.")

        # Encrypt AES key
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        with open("encrypted_aes_key.bin", "wb") as f:
            f.write(encrypted_aes_key)

        self.logger.info("AES key encrypted using RSA.")

        # Sign
        signature = private_key.sign(
            encrypted_message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        with open("signature.bin", "wb") as f:
            f.write(signature)

        self.logger.info("Digital signature created.")
        self.logger.info("Sender finished successfully.")

    def toggle_public(self):
        if self.hidden:
            self.log_box.configure(state="normal")
            self.log_box.insert("end", "\n--- PUBLIC KEY ---\n" + self.public_key_text + "\n")
            self.log_box.configure(state="disabled")
        self.hidden = not self.hidden

    def toggle_cipher(self):
        if self.hidden:
            self.log_box.configure(state="normal")
            self.log_box.insert("end", "\n--- CIPHERTEXT ---\n" + self.cipher_text + "\n")
            self.log_box.configure(state="disabled")
        self.hidden = not self.hidden


if __name__ == "__main__":
    app = SenderApp()
    app.mainloop()
