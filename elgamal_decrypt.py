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


def encode_string_to_int(msg: str) -> int:
    return int.from_bytes(msg.encode("utf-8"), byteorder="big")


def decode_int_to_string(n: int) -> str:
    """Convert an integer back to a UTF-8 string (inverse of encode_string_to_int)."""
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, byteorder="big").decode("utf-8")


def decrypt_integer_message(c1: int, c2: int, p: int, g: int, y: int, x: int):
    priv = ElGamalPrivateKey(p=p, g=g, x=x)
    ciphertext = (c1, c2)
    
    # Display in same format as encryption file
    print(f"Public key:  p={p}, g={g}, y={y}")
    print(f"Private key: x={x}")
    
    print(f"\nCiphertext (c1, c2) = {ciphertext}")
    
    m_recovered = elgamal_decrypt(ciphertext, priv)
    print(f"Decrypted message  = {m_recovered}")
    return m_recovered


def decrypt_string_message(c1: int, c2: int, p: int, g: int, y: int, x: int):
    priv = ElGamalPrivateKey(p=p, g=g, x=x)
    ciphertext = (c1, c2)
    
    # Display in same format as encryption file
    print(f"Public key:  p={p}, g={g}, y={y}")
    print(f"Private key: x={x}")
    
    print(f"\nCiphertext (c1, c2) = {ciphertext}")
    
    m_recovered = elgamal_decrypt(ciphertext, priv)
    
    try:
        msg_recovered = decode_int_to_string(m_recovered)
        print(f"Decrypted int:     {m_recovered}")
        print(f"Decrypted string:  {msg_recovered}")
        return msg_recovered
    except ValueError as e:
        print(f"\nError: {e}")
        print("This might indicate:")
        print("  - The message was not a string (try using decrypt_integer_message instead)")
        print("  - The decryption failed (wrong key or corrupted ciphertext)")
        print("  - The decrypted integer doesn't represent valid UTF-8 text")
        raise


def find_private_key(p: int, g: int, y: int, max_attempts: int = 1000000):
    if p > max_attempts:
        return None
    
    print(f"Attempting to derive private key from public information...")
    for x in range(1, min(p, max_attempts + 1)):
        if pow(g, x, p) == y:
            print(f"Found private key: x = {x}")
            return x
    return None


def interactive_decrypt():
    """
    Interactive function to decrypt messages by prompting user for input.
    Only asks for public information and attempts to derive private key.
    """
    try:
        print("Enter public key information (from encryption output):")
        p = int(input("  p (prime modulus): "))
        g = int(input("  g (generator): "))
        y = int(input("  y (public key): "))
        print("\nEnter ciphertext (from encryption output):")
        c1 = int(input("  c1: "))
        c2 = int(input("  c2: "))
        print("\n(Optional) Enter 'Encoded as int' value from encryption output for verification:")
        print("  (Press Enter to skip this verification)")
        expected_int_input = input("  Expected encoded int: ").strip()
        expected_int = None
        if expected_int_input:
            try:
                expected_int = int(expected_int_input)
            except ValueError:
                print("  (Invalid integer, skipping verification)")
        x = find_private_key(p, g, y)
        if x is None:
            print("\nCould not automatically derive private key (prime too large).")
            print("Enter private key:")
            x = int(input("  x (private key): ")) # Verify the private key is correct: g^x mod p should equal y
        y_verify = pow(g, x, p)
        if y_verify != y:
            print(f"\nERROR: Private key verification failed!")
            print(f"  Expected: g^x mod p = {y}")
            print(f"  Got:      g^x mod p = {y_verify}")
            print(f"  This means the private key x={x} is incorrect for the given public key.")
            print(f"\n  Please verify:")
            print(f"    - p = {p}")
            print(f"    - g = {g}")
            print(f"    - y = {y}")
            print(f"    - x = {x}")
            print(f"    Make sure these values match exactly from the encryption output.")
            raise ValueError(f"Private key x={x} does not match public key y={y}")
        if c1 < 1 or c1 >= p:
            print(f"\nWARNING: c1={c1} is not in valid range [1, {p-1}]")
        if c2 < 1 or c2 >= p:
            print(f"\nWARNING: c2={c2} is not in valid range [1, {p-1}]")
        print(f"\nVerification test:")
        print(f"  Testing: g^x mod p should equal y")
        print(f"  {g}^{x} mod {p} = {y_verify}")
        if y_verify == y:
            print(f"  ✓ Private key verification passed")
        else:
            print(f"  ✗ Private key verification FAILED")
        print()
        priv = ElGamalPrivateKey(p=p, g=g, x=x)
        ciphertext = (c1, c2)
        print(f"\n" + "="*60)
        print(f"Input Values Summary (verify these match encryption output):")
        print(f"="*60)
        print(f"Public key:")
        print(f"  p = {p}")
        print(f"  g = {g}")
        print(f"  y = {y}")
        print(f"Private key:")
        print(f"  x = {x}")
        print(f"Ciphertext:")
        print(f"  c1 = {c1}")
        print(f"  c2 = {c2}")
        print(f"="*60)
        print(f"\nPublic key:  p={p}, g={g}, y={y}")
        print(f"Private key: x={x}")
        print(f"\nCiphertext (c1, c2) = {ciphertext}")
        print(f"\nDecryption calculation:")
        print(f"  Step 1: s = c1^x mod p")
        print(f"         s = {c1}^{x} mod {p}")
        s = pow(c1, x, p)
        print(f"         s = {s}")
        
        print(f"  Step 2: s_inv = s^(-1) mod p")
        s_inv = modinv(s, p)
        print(f"         s_inv = {s_inv}")
        
        print(f"  Step 3: m = c2 * s_inv mod p")
        print(f"         m = {c2} * {s_inv} mod {p}")
        m_recovered = (c2 * s_inv) % p
        print(f"         m = {m_recovered}")
        
        print(f"\nDecryption details:")
        print(f"  Decrypted integer: {m_recovered}")
        print(f"  Integer in hex: {hex(m_recovered)}")
        if expected_int is not None:
            if m_recovered == expected_int:
                print(f"  ✓ Decrypted integer matches expected value!")
            else:
                print(f"  ✗ ERROR: Decrypted integer does NOT match expected value!")
                print(f"    Expected: {expected_int}")
                print(f"    Got:      {m_recovered}")
                print(f"    Difference: {abs(m_recovered - expected_int)}")
                print(f"    This confirms the decryption is incorrect.")
                print(f"    Please double-check all input values (p, g, y, x, c1, c2)")
        try:
            msg_recovered = decode_int_to_string(m_recovered)
        except Exception as e:
            print(f"\nERROR: Failed to decode integer to string: {e}")
            print(f"  This usually means the decrypted integer is incorrect.")
            print(f"  Please verify:")
            print(f"    1. Private key x is correct (from encryption output)")
            print(f"    2. Ciphertext (c1, c2) is correct (from encryption output)")
            print(f"    3. Public key (p, g, y) is correct (from encryption output)")
            raise
        verify_int = encode_string_to_int(msg_recovered)
        if verify_int != m_recovered:
            print(f"\nERROR: String encoding/decoding verification failed!")
            print(f"  Decrypted int: {m_recovered}")
            print(f"  Decrypted string: '{msg_recovered}'")
            print(f"  Re-encoded int: {verify_int}")
            print(f"  This means the decrypted integer does not match the encoded string.")
            print(f"  The decryption produced an incorrect integer value.")
            print(f"  Please check:")
            print(f"    - Private key x (should match 'Private key: x=...' from encryption)")
            print(f"    - Ciphertext c1, c2 (should match 'Ciphertext (c1, c2) = (...)' from encryption)")
            print(f"    - Public key p, g, y (should match 'Public key: p=..., g=..., y=...' from encryption)")
            print()
        print(f"Decrypted string:  {msg_recovered}")
    except ValueError as e:
        print(f"\nError: Invalid input - {e}")
        print("Please make sure all values are valid integers.")
    except KeyboardInterrupt:
        print("\n\nDecryption cancelled by user.")
    except Exception as e:
        print(f"\nError during decryption: {e}")


if __name__ == "__main__":
    interactive_decrypt()