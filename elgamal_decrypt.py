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


def interactive_decrypt():
    """
    Interactive function to decrypt messages by prompting user for input.
    Uses the format from elgamal_sending_project.py: message, c1, c2, p, g, x
    """
    try:
        p = int(input("p: "))
        g = int(input("g: "))
        x = int(input("x: "))
        c1 = int(input("c1: "))
        c2 = int(input("c2: "))
        
        priv = ElGamalPrivateKey(p=p, g=g, x=x)
        ciphertext = (c1, c2)
        m_recovered = elgamal_decrypt(ciphertext, priv)
        
        print(f"message={m_recovered}")
    except ValueError as e:
        print(f"Error: Invalid input - {e}")
    except KeyboardInterrupt:
        print("\nDecryption cancelled by user.")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    interactive_decrypt()
