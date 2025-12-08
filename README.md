# METCS789 Cryptography Project

Choose your encryption method: **RSA** or **ElGamal**

## RSA

**A (Sender):** Run `python rsa_a.py` - Enter B's public key, encrypt your message, send the ciphertext

**B (Receiver):** Run `python rsa_b.py` - Generate keys, share public key with A, receive ciphertext, decrypt

**C (Interceptor):** Run `python rsa_c.py` - Enter intercepted public key and ciphertext, try to decrypt

## ElGamal

**A (Sender):** Run `python elgamal_sending_project.py` - Copy the public key (p, g, y) and ciphertext (c1, c2), send to B

**B (Receiver):** Run `python elgamal_receiving_project.py` - Enter the public key and ciphertext from A, decrypt the message

**C (Interceptor):** Run `python elgamal_decrypt.py` - Enter intercepted public key and ciphertext, try to find the private key and decrypt


