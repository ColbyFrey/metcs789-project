"""
RSA Operations: Encryption, Decryption, Modular Inverse, and Chinese Remainder Theorem

This module implements core RSA operations including:
- RSA encryption and decryption
- Modular inverse computation
- Chinese Remainder Theorem
"""


def gcd(a: int, b: int) -> int:
    """Euclidean algorithm for greatest common divisor."""
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a: int, b: int) -> tuple:
    """Extended Euclidean Algorithm: returns (g, x, y) s.t. ax + by = g = gcd(a, b)."""
    if b == 0:
        return a, 1, 0
    g, x1, y1 = extended_gcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return g, x, y


def mod_inverse(a: int, m: int) -> int:
    """Compute modular inverse using extended Euclidean algorithm."""
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        raise ValueError(f"No modular inverse for {a} mod {m}")
    return x % m


def mod_pow(base: int, exponent: int, modulus: int) -> int:
    """Fast modular exponentiation."""
    result = 1
    base = base % modulus
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        exponent >>= 1
        base = (base * base) % modulus
    return result


def euler_totient(n: int) -> int:
    """Compute Euler's totient function φ(n)."""
    result = n
    p = 2
    while p * p <= n:
        if n % p == 0:
            while n % p == 0:
                n //= p
            result -= result // p
        p += 1
    if n > 1:
        result -= result // n
    return result


def chinese_remainder_theorem(a1: int, m1: int, a2: int, m2: int) -> int:
    """
    Chinese Remainder Theorem for two moduli.
    Find x such that x ≡ a1 (mod m1) and x ≡ a2 (mod m2).
    """
    g, x, y = extended_gcd(m1, m2)
    if g != 1:
        raise ValueError("Moduli must be coprime")
    
    M = m1 * m2
    return (a1 * m2 * y + a2 * m1 * x) % M


# RSA Encryption/Decryption
def rsa_encryption_decryption():
    """
    RSA Encryption and Decryption
    
    Demonstrates RSA encryption and decryption with given parameters.
    """
    print("=" * 60)
    print("RSA Encryption and Decryption")
    print("=" * 60)
    
    # Example RSA parameters
    p = 61
    q = 53
    n = p * q  # 3233
    phi_n = (p - 1) * (q - 1)  # 3120
    e = 17  # Public exponent
    d = mod_inverse(e, phi_n)  # Private exponent
    
    print(f"RSA Parameters:")
    print(f"  p = {p}")
    print(f"  q = {q}")
    print(f"  n = p * q = {n}")
    print(f"  φ(n) = (p-1)(q-1) = {phi_n}")
    print(f"  Public exponent e = {e}")
    print(f"  Private exponent d = {d}")
    print(f"  Verification: e * d mod φ(n) = {e * d % phi_n}")
    print()
    
    # Encrypt a message
    message = 65  # 'A' in ASCII
    print(f"Original message: m = {message}")
    
    ciphertext = mod_pow(message, e, n)
    print(f"Encrypted: c = m^e mod n = {ciphertext}")
    
    decrypted = mod_pow(ciphertext, d, n)
    print(f"Decrypted: m = c^d mod n = {decrypted}")
    print(f"✓ {'Success' if decrypted == message else 'Error'}")
    print()


# Finding Modular Inverse
def modular_inverse_examples():
    """
    Finding Modular Inverse
    
    Demonstrates computing modular inverses using extended Euclidean algorithm.
    """
    print("=" * 60)
    print("Finding Modular Inverse")
    print("=" * 60)
    
    # Example problems
    problems = [
        (7, 26),   # Find 7^(-1) mod 26
        (17, 3120),  # Find 17^(-1) mod 3120 (RSA example)
        (3, 11),   # Find 3^(-1) mod 11
        (5, 23),   # Find 5^(-1) mod 23
    ]
    
    for a, m in problems:
        try:
            inv = mod_inverse(a, m)
            print(f"Find {a}^(-1) mod {m}")
            print(f"  Solution: {a}^(-1) ≡ {inv} (mod {m})")
            print(f"  Verification: {a} * {inv} mod {m} = {a * inv % m}")
            print()
        except ValueError as e:
            print(f"  Error: {e}")
            print()


# Chinese Remainder Theorem
def chinese_remainder_examples():
    """
    Chinese Remainder Theorem
    
    Demonstrates solving systems of congruences using CRT.
    """
    print("=" * 60)
    print("Chinese Remainder Theorem")
    print("=" * 60)
    
    # Example problems
    problems = [
        # x ≡ 2 (mod 3), x ≡ 3 (mod 5), x ≡ 2 (mod 7)
        ([2, 3, 2], [3, 5, 7]),
        # x ≡ 1 (mod 5), x ≡ 2 (mod 7)
        ([1, 2], [5, 7]),
        # x ≡ 3 (mod 7), x ≡ 5 (mod 11)
        ([3, 5], [7, 11]),
    ]
    
    for a_list, m_list in problems:
        print(f"Solve the system:")
        for i, (a, m) in enumerate(zip(a_list, m_list)):
            print(f"  x ≡ {a} (mod {m})")
        
        # Solve pairwise using CRT
        if len(a_list) == 2:
            x = chinese_remainder_theorem(a_list[0], m_list[0], a_list[1], m_list[1])
            M = m_list[0] * m_list[1]
        else:
            # For more than 2 equations, solve iteratively
            x = chinese_remainder_theorem(a_list[0], m_list[0], a_list[1], m_list[1])
            M = m_list[0] * m_list[1]
            for i in range(2, len(a_list)):
                x = chinese_remainder_theorem(x, M, a_list[i], m_list[i])
                M *= m_list[i]
        
        print(f"  Solution: x ≡ {x} (mod {M})")
        
        # Verify
        print(f"  Verification:")
        for a, m in zip(a_list, m_list):
            result = x % m
            print(f"    {x} mod {m} = {result} {'✓' if result == a else '✗'}")
        print()


# Additional helper: RSA using CRT for faster decryption
def rsa_decrypt_crt(ciphertext: int, d: int, p: int, q: int) -> int:
    """
    RSA decryption using Chinese Remainder Theorem for efficiency.
    """
    n = p * q
    dp = d % (p - 1)
    dq = d % (q - 1)
    
    mp = mod_pow(ciphertext, dp, p)
    mq = mod_pow(ciphertext, dq, q)
    
    # Use CRT to combine results
    q_inv = mod_inverse(q, p)
    h = (q_inv * (mp - mq)) % p
    m = mq + h * q
    
    return m % n


if __name__ == "__main__":
    rsa_encryption_decryption()
    modular_inverse_examples()
    chinese_remainder_examples()
    
    print("=" * 60)
    print("Bonus: RSA Decryption using CRT")
    print("=" * 60)
    p, q = 61, 53
    n = p * q
    phi_n = (p - 1) * (q - 1)
    e = 17
    d = mod_inverse(e, phi_n)
    
    message = 65
    ciphertext = mod_pow(message, e, n)
    decrypted_crt = rsa_decrypt_crt(ciphertext, d, p, q)
    decrypted_normal = mod_pow(ciphertext, d, n)
    
    print(f"Message: {message}")
    print(f"Ciphertext: {ciphertext}")
    print(f"Decrypted (normal): {decrypted_normal}")
    print(f"Decrypted (CRT): {decrypted_crt}")
    print(f"Both methods match: {decrypted_normal == decrypted_crt}")

