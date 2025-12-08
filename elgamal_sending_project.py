import secrets
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

if __name__ == "__main__":
    
    p = 467  # Small prime to allow private key derivation
    g = 2
    pub, priv = elgamal_keygen(p, g)
    
    message = secrets.randbelow(p - 1) + 1
    
    c1, c2 = elgamal_encrypt(message, pub)
    
    # Output: message, c1, c2, p, g, y (public values)
    print(f"message={message}")
    print(f"c1={c1}")
    print(f"c2={c2}")
    print(f"p={p}")
    print(f"g={g}")
    print(f"x={priv.x}")
    print(f"y={pub.y}")

