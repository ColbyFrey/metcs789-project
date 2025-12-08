from dataclasses import dataclass


def egcd(a: int, b: int):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return g, x, y


def modinv(a: int, m: int) -> int:
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError(f"No modular inverse for {a} mod {m}")
    return x % m


@dataclass
class ElGamalPrivateKey:
    p: int
    g: int
    x: int


def elgamal_decrypt(ciphertext, priv: ElGamalPrivateKey) -> int:
    c1, c2 = ciphertext
    p = priv.p
    s = pow(c1, priv.x, p)
    s_inv = modinv(s, p)
    m = (c2 * s_inv) % p
    return m


def find_private_key(p: int, g: int, y: int, max_attempts: int = 1000000):
    """
    Attempt to find private key x such that g^x mod p = y.
    This is the discrete logarithm problem - only feasible for small primes.
    """
    if p > max_attempts:
        return None
    
    for x in range(1, min(p, max_attempts + 1)):
        if pow(g, x, p) == y:
            return x
    return None


def interactive_decrypt():
    """
    Interactive function to decrypt messages using only public domain values.
    Requires: p, g, y (public key), c1, c2 (ciphertext)
    Attempts to derive private key x from public key y.
    """
    try:
        p = int(input("p: "))
        g = int(input("g: "))
        y = int(input("y: "))
        c1 = int(input("c1: "))
        c2 = int(input("c2: "))
        
        # Try to find private key x from public key y
        x = find_private_key(p, g, y)
        if x is None:
            raise ValueError(f"Cannot derive private key (prime too large). For decryption, you need the private key x.")
        
        priv = ElGamalPrivateKey(p=p, g=g, x=x)
        ciphertext = (c1, c2)
        m_recovered = elgamal_decrypt(ciphertext, priv)
        
        print(f"message={m_recovered}")
    except ValueError as e:
        print(f"Error: {e}")
    except KeyboardInterrupt:
        print("\nDecryption cancelled by user.")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    interactive_decrypt()
