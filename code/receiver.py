import customtkinter as ctk
import logging
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

class ReceiverApp(ctk.CTk):

    def __init__(self):
        super().__init__()
        self.title("Secure Receiver")
        self.geometry("800x500")

        self.decrypt_btn = ctk.CTkButton(self, text="Verify & Decrypt", command=self.decrypt)
        self.decrypt_btn.pack(pady=10)

        self.output = ctk.CTkTextbox(self)
        self.output.pack(fill="both", expand=True, padx=10, pady=10)
        self.output.configure(state="disabled")

        self.logger = logging.getLogger("RECEIVER_GUI")
        self.logger.setLevel(logging.INFO)

    def log(self, msg):
        self.output.configure(state="normal")
        self.output.insert("end", msg + "\n")
        self.output.configure(state="disabled")

    def decrypt(self):
        self.log("Receiver started.")

        with open("private_key.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), None)

        with open("public_key.pem", "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())

        encrypted_message = open("encrypted_message.bin", "rb").read()
        encrypted_key = open("encrypted_aes_key.bin", "rb").read()
        signature = open("signature.bin", "rb").read()

        try:
            public_key.verify(
                signature,
                encrypted_message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            self.log("Signature verified ✔")
        except InvalidSignature:
            self.log("Signature invalid ✖")
            return

        aes_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        iv = encrypted_message[:16]
        ciphertext = encrypted_message[16:]

        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        message = decryptor.update(ciphertext) + decryptor.finalize()

        self.log("\nDecrypted Message:")
        self.log(message.decode())
        self.log("\nReceiver finished successfully.")


if __name__ == "__main__":
    app = ReceiverApp()
    app.mainloop()
