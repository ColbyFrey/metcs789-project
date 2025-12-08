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
    # Ensure a is in range [0, m)
    a = a % m
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError(f"No modular inverse for {a} mod {m}")
    # Ensure result is positive
    result = x % m
    return result

@dataclass
class ElGamalPrivateKey:
    p: int
    g: int
    x: int 


def elgamal_decrypt(ciphertext, priv: ElGamalPrivateKey) -> int:
    """
    Decrypt an ElGamal ciphertext using the private key.
    
    Args:
        ciphertext: Tuple (c1, c2) representing the encrypted message
        priv: ElGamalPrivateKey containing p, g, and x (private key)
    
    Returns:
        The decrypted message as an integer
    """
    c1, c2 = ciphertext
    p = priv.p
    s = pow(c1, priv.x, p)
    s_inv = modinv(s, p)
    m = (c2 * s_inv) % p
    # Debug output
    print(f"[DEBUG] Decryption steps:")
    print(f"  c1 = {c1}, c2 = {c2}")
    print(f"  p = {p}, x (private key) = {priv.x}")
    print(f"  s = c1^x mod p = {c1}^{priv.x} mod {p} = {s}")
    print(f"  s_inv = modinv({s}, {p}) = {s_inv}")
    print(f"  m = (c2 * s_inv) mod p = ({c2} * {s_inv}) mod {p} = {m}")
    return m


def receive_and_decrypt_integer(c1: int, c2: int, priv: ElGamalPrivateKey) -> int:
    """
    Receive ciphertext and decrypt it to an integer message.
    
    Args:
        c1: First component of the ElGamal ciphertext
        c2: Second component of the ElGamal ciphertext
        priv: ElGamalPrivateKey for decryption
    
    Returns:
        The decrypted integer message
    """
    ciphertext = (c1, c2)
    m_int = elgamal_decrypt(ciphertext, priv)
    return m_int


def demo_receive_integer():
    
    print("\nEnter the private key parameters (from the sending script):")
    try:
        p_input = input("Enter p (or press Enter for default 467): ").strip()
        p = int(p_input) if p_input else 467
        
        g_input = input("Enter g (or press Enter for default 2): ").strip()
        g = int(g_input) if g_input else 2
        
        x_input = input("Enter x): ").strip()
        if not x_input:
            raise ValueError("Private key x is required!")
        x = int(x_input)
        
        priv = ElGamalPrivateKey(p=p, g=g, x=x)
        
        print("\nEnter ciphertext components:")
        c1_input = input("Enter c1: ")
        c2_input = input("Enter c2: ")
        c1 = int(c1_input)
        c2 = int(c2_input)
        
        message_int = receive_and_decrypt_integer(c1, c2, priv)
        print(f"\nDecrypted integer: {message_int}")
    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Decryption error: {e}")


if __name__ == "__main__":
    demo_receive_integer()
