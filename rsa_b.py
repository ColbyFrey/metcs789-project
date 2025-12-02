# RSA for B (receiver)
# B makes keys, gives public key to A, decrypts stuff

from rsa_operations import gcd, mod_inverse, mod_pow
import secrets

DEFAULT_E = 17
SMALL_PRIMES = [11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]


def get_int_input(prompt, min_val=None, max_val=None):
    """Safely get integer input with validation."""
    while True:
        try:
            value = input(prompt).strip()
            if not value:
                return None
            num = int(value)
            if min_val is not None and num < min_val:
                print(f"error: value must be >= {min_val}")
                continue
            if max_val is not None and num > max_val:
                print(f"error: value must be <= {max_val}")
                continue
            return num
        except ValueError:
            print("error: enter a valid integer")
        except KeyboardInterrupt:
            print("\ninterrupted")
            return None


def is_prime_simple(n):
    """Simple primality test for small numbers."""
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    i = 3
    while i * i <= n:
        if n % i == 0:
            return False
        i += 2
    return True


def generate_keys():
    print("\nB: Generate RSA Keys")
    
    print("\n1. enter primes manually")
    print("2. generate random primes")
    choice = input("choice (1 or 2, default 1): ").strip() or "1"
    
    if choice == "1":
        print("\nenter two small primes (e.g., 11, 13, 17, 19, 23):")
        p = get_int_input("p = ", min_val=2)
        if p is None:
            return None
        if not is_prime_simple(p):
            print(f"error: {p} is not prime")
            return None
        
        q = get_int_input("q = ", min_val=2)
        if q is None:
            return None
        if not is_prime_simple(q):
            print(f"error: {q} is not prime")
            return None
        
        if p == q:
            print("error: p and q must be different")
            return None
    else:
        p = secrets.choice(SMALL_PRIMES)
        q = secrets.choice([x for x in SMALL_PRIMES if x != p])
        print(f"generated: p={p}, q={q}")
    
    n = p * q
    print(f"\nn = p × q = {p} × {q} = {n}")
    
    phi_n = (p - 1) * (q - 1)
    print(f"φ(n) = (p-1) × (q-1) = {p-1} × {q-1} = {phi_n}")
    
    print("\nchoose public exponent e (common: 3, 17, 65537):")
    e_input = input("e (or Enter for 17): ").strip()
    if e_input:
        try:
            e = int(e_input)
            if e < 2:
                print(f"error: e must be >= 2")
                return None
        except ValueError:
            print("error: enter a valid integer")
            return None
    else:
        e = DEFAULT_E
    
    if e >= phi_n:
        print(f"error: e ({e}) must be < φ(n) ({phi_n})")
        return None
    
    if gcd(e, phi_n) != 1:
        print(f"error: gcd({e}, {phi_n}) != 1, choose different e")
        return None
    
    try:
        d = mod_inverse(e, phi_n)
    except ValueError:
        print(f"error: no modular inverse for e={e} mod φ(n)={phi_n}")
        return None
    
    print(f"d = {d}")
    print(f"check: e*d mod φ(n) = {(e * d) % phi_n}")
    
    print("\nKeys generated")
    print(f"\nPublic key (share with A): n={n}, e={e}")
    print(f"\nPrivate key (keep secret):")
    print(f"  n = {n}")
    print(f"  d = {d}")
    print(f"  p = {p}")
    print(f"  q = {q}")
    print(f"  φ(n) = {phi_n}")
    
    return {
        'p': p,
        'q': q,
        'n': n,
        'e': e,
        'd': d,
        'phi_n': phi_n
    }


def decrypt_message(c, n, d):
    print("\nB: Decrypt Message")
    
    if c < 0 or c >= n:
        print(f"error: ciphertext {c} must be in range [0, {n})")
        return None
    
    print(f"ciphertext: c={c}, using d={d}, n={n}")
    print(f"\nm = c^d mod n = {c}^{d} mod {n}")
    
    m = mod_pow(c, d, n)
    print(f"decrypted: m = {m}")
    
    return m


def main():
    print("RSA Program for B (Receiver)")
    print("\nB generates keys, shares public key with A, decrypts messages")
    
    keys = None
    
    try:
        while True:
            print("\n1. generate new keys")
            print("2. show public key")
            print("3. decrypt message")
            print("4. show all keys")
            print("5. exit")
            
            choice = input("\nselect: ").strip()
            
            if choice == "1":
                keys = generate_keys()
            
            elif choice == "2":
                if keys:
                    print(f"\nPublic key: n={keys['n']}, e={keys['e']}")
                    print("Give this to A")
                else:
                    print("generate keys first")
            
            elif choice == "3":
                if keys:
                    c = get_int_input("ciphertext from A: ", min_val=0)
                    if c is not None:
                        decrypt_message(c, keys['n'], keys['d'])
                else:
                    print("generate keys first")
            
            elif choice == "4":
                if keys:
                    print(f"public: n={keys['n']}, e={keys['e']}")
                    print(f"private: n={keys['n']}, d={keys['d']}")
                    print(f"primes: p={keys['p']}, q={keys['q']}")
                    print(f"φ(n)={keys['phi_n']}")
                else:
                    print("generate keys first")
            
            elif choice == "5":
                break
            
            else:
                print("invalid choice")
    
    except KeyboardInterrupt:
        print("\ninterrupted, exiting")


if __name__ == "__main__":
    main()
