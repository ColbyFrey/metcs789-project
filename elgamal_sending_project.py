import secrets
import string
from dataclasses import dataclass

def egcd(a: int, b: int):
    """Extended Euclidean Algorithm: returns (g, x, y) s.t. ax + by = g = gcd(a, b)."""
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return g, x, y


def modinv(a: int, m: int) -> int:
    """Modular inverse of a modulo m. Raises ValueError if inverse does not exist."""
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError(f"No modular inverse for {a} mod {m}")
    return x % m

@dataclass
class ElGamalPublicKey:
    p: int 
    g: int  
    y: int  

@dataclass
class ElGamalPrivateKey:
    p: int
    g: int
    x: int 

def elgamal_keygen(p: int, g: int):
    
    if p <= 2:
        raise ValueError("p must be a prime > 2")
    if not (1 < g < p):
        raise ValueError("g must satisfy 1 < g < p")

    x = secrets.randbelow(p - 2) + 1
    y = pow(g, x, p)

    pub = ElGamalPublicKey(p=p, g=g, y=y)
    priv = ElGamalPrivateKey(p=p, g=g, x=x)
    return pub, priv


def elgamal_encrypt(m: int, pub: ElGamalPublicKey):
    if not (0 < m < pub.p):
        raise ValueError(f"Message m must be in range 1..{pub.p-1}")
    k = secrets.randbelow(pub.p - 2) + 1
    c1 = pow(pub.g, k, pub.p)
    s = pow(pub.y, k, pub.p)
    c2 = (m * s) % pub.p

    return c1, c2


def elgamal_decrypt(ciphertext, priv: ElGamalPrivateKey) -> int:
    c1, c2 = ciphertext
    p = priv.p
    s = pow(c1, priv.x, p)
    s_inv = modinv(s, p)
    m = (c2 * s_inv) % p
    return m

def encode_string_to_int(msg: str) -> int:
    """
    Convert a short ASCII string to an integer.
    NOTE: The resulting integer must be < p to be encryptable.
    """
    return int.from_bytes(msg.encode("utf-8"), byteorder="big")


def decode_int_to_string(n: int) -> str:
    """Convert an integer back to a UTF-8 string (inverse of encode_string_to_int)."""
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, byteorder="big").decode("utf-8")

def demo_integer_message():
    p = 467       
    g = 2       
    pub, priv = elgamal_keygen(p, g)

    print(f"Public key:  p={pub.p}, g={pub.g}, y={pub.y}")
    print(f"Private key: x={priv.x}")

    message = secrets.randbelow(p - 1) + 1 
    print(f"\nOriginal message m = {message}")

    c = elgamal_encrypt(message, pub)
    print(f"Ciphertext (c1, c2) = {c}")

    m_recovered = elgamal_decrypt(c, priv)
    print(f"Decrypted message  = {m_recovered}")


def demo_string_message():
    p = 2**255 - 19
    g = 3
    pub, priv = elgamal_keygen(p, g)
    sentences = [
        "Hello world!",
        "Secret message here.",
        "Python is great.",
        "Data is secure now.",
        "Nice weather today.",
        "I love cryptography.",
        "ElGamal encryption works!",
        "Math is very fun.",
        "Code should be clean.",
        "Use strong encryption.",
        "The fox jumps high.",
        "Learning is awesome.",
        "Security matters most.",
        "Keep data protected.",
        "Encrypt everything safely."
    ]
    
    valid_sentences = []
    for sentence in sentences:
        m_int = encode_string_to_int(sentence)
        if m_int < p:
            valid_sentences.append(sentence)
    
    if not valid_sentences:
        raise ValueError("No sentences fit in the prime size!")
    
    msg = secrets.choice(valid_sentences)
    m_int = encode_string_to_int(msg)

    print(f"Original string: {msg}")
    print(f"Encoded as int:  {m_int}")

    c = elgamal_encrypt(m_int, pub)
    print(f"Ciphertext (c1, c2) = {c}")

    m_recovered = elgamal_decrypt(c, priv)
    msg_recovered = decode_int_to_string(m_recovered)
    print(f"Decrypted int:     {m_recovered}")
    print(f"Decrypted string:  {msg_recovered}")

if __name__ == "__main__":
    demo_integer_message()
    demo_string_message()