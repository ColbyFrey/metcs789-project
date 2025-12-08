# RSA for C (interceptor)
# C tries to decrypt with only public info

import math
import pollard_rho
from rsa_operations import gcd, mod_inverse, mod_pow

MAX_FACTOR_SEARCH = 10000


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


def try_intercept():
    print("\nC: Try to Intercept and Decrypt")
    
    print("\nC intercepted public key and ciphertext")
    
    n = get_int_input("n = ", min_val=2)
    if n is None:
        return
    
    e = get_int_input("e = ", min_val=2)
    if e is None:
        return
    
    c = get_int_input("c = ", min_val=0)
    if c is None:
        return
    
    if c >= n:
        print(f"error: ciphertext {c} must be < n ({n})")
        return
    
    print(f"\nC knows: n={n}, e={e}, c={c}")
    print(f"C doesn't know: p, q, d, φ(n)")
    
    print("\nDecryption: m = c^d mod n")
    print("Problem: C doesn't have d")
    print("B has d, so B can decrypt")
    print("C needs to find d first")
    
    print("\nTo find d:")
    print("1. factor n = p*q")
    print("2. compute φ(n) = (p-1)(q-1)")
    print("3. compute d = e^(-1) mod φ(n)")
    print("4. decrypt: m = c^d mod n")
    
    print(f"\ntrying to factor n={n}")
    found = False
   # max_search = min(int(n**0.5) + 1, MAX_FACTOR_SEARCH)
    max_search = math.floor(math.sqrt(n) / 2)
    p = pollard_rho.factor_pollard_p1(n, max_search)
    print(f"max search limit: {max_search}")
    if p is not None:
        q = n // p
        print(f"found: p={p}, q={q}")
        found = True
        
        phi_n = (p - 1) * (q - 1)
        print(f"φ(n) = {phi_n}")
        
        if gcd(e, phi_n) == 1:
            try:
                d = mod_inverse(e, phi_n)
                print(f"d = {d}")
                
                print(f"\nC can decrypt:")
                print(f"m = c^{d} mod {n}")
                m = mod_pow(c, d, n)
                print(f"decrypted: m = {m}")
                print(f"(only works because n is small: {n})")
                print(f"for large n, factoring is impossible")
            except ValueError:
                print(f"error: no modular inverse for e={e} mod φ(n)={phi_n}")
        else:
            print(f"gcd(e, φ(n)) != 1")
    else:
        print(f"can't factor n={n}")
        if max_search >= MAX_FACTOR_SEARCH:
            print(f"(search limited to {MAX_FACTOR_SEARCH} to prevent hanging)")
        print(f"for real RSA (256+ bits), this is impossible")
        print(f"RSA is secure - C can't decrypt")
    
"""    for i in range(2, max_search):


        if n % i == 0:
            p = i
            q = n // i
            print(f"found: p={p}, q={q}")
            found = True
            
            phi_n = (p - 1) * (q - 1)
            print(f"φ(n) = {phi_n}")
            
            if gcd(e, phi_n) == 1:
                try:
                    d = mod_inverse(e, phi_n)
                    print(f"d = {d}")
                    
                    print(f"\nC can decrypt:")
                    print(f"m = {c}^{d} mod {n}")
                    m = mod_pow(c, d, n)
                    print(f"decrypted: m = {m}")
                    print(f"(only works because n is small: {n})")
                    print(f"for large n, factoring is impossible")
                except ValueError:
                    print(f"error: no modular inverse for e={e} mod φ(n)={phi_n}")
            else:
                print(f"gcd(e, φ(n)) != 1")
            break
    
    if not found:
        print(f"can't factor n={n}")
        if max_search >= MAX_FACTOR_SEARCH:
            print(f"(search limited to {MAX_FACTOR_SEARCH} to prevent hanging)")
        print(f"for real RSA (256+ bits), this is impossible")
        print(f"RSA is secure - C can't decrypt")

"""
def main():
    print("RSA Program for C (Interceptor)")
    print("\nC intercepts public key and ciphertext, tries to decrypt")
    
    try:
        while True:
            print("\n1. try to intercept and decrypt")
            print("2. exit")
            
            choice = input("\nselect: ").strip()
            
            if choice == "1":
                try_intercept()
                print("\n---")
            
            elif choice == "2":
                break
            
            else:
                print("invalid choice")
    
    except KeyboardInterrupt:
        print("\ninterrupted, exiting")


if __name__ == "__main__":
    main()
