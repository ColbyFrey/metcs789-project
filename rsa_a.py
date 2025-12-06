# RSA for A (sender)
# A gets public key from B, encrypts, sends to B

from rsa_operations import mod_pow


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


def get_public_key():
    print("\nA: Get Public Key from B")
    print("\nB gives you their public key (n, e)")
    
    n = get_int_input("n = ", min_val=2)
    if n is None:
        return None, None
    
    e = get_int_input("e = ", min_val=2)
    if e is None:
        return None, None
    
    print(f"n={n}, e={e}")
    
    return n, e


def encrypt_message(n, e):
    print("\nA: Encrypt Message")
    print(f"using n={n}, e={e}")
    
    m = get_int_input("\nmessage as number: ", min_val=0, max_val=n-1)
    if m is None:
        return None
    
    if m < 0:
        print(f"error: message must be >= 0")
        return None
    if m >= n:
        print(f"error: message {m} must be < n ({n})")
        return None
    
    print(f"\nc = m^e mod n = {m}^{e} mod {n}")
    
    c = mod_pow(m, e, n)
    
    print(f"ciphertext: c = {c}")
    print("send this to B")
    
    return c

def main():
    print("RSA Program for A (Sender)")
    print("\nA gets public key from B, encrypts, sends ciphertext")
    
    n = None
    e = None
    
    try:
        while True:
            print("\n1. get public key from B")
            print("2. encrypt message")
            print("3. show current public key")
            print("4. exit")
            
            choice = input("\nselect: ").strip()
            
            if choice == "1":
                result = get_public_key()
                if result[0] is not None:
                    n, e = result
            
            elif choice == "2":
                if n and e:
                    encrypt_message(n, e)
                else:
                    print("get public key first")
            
            elif choice == "3":
                if n and e:
                    print(f"n={n}, e={e}")
                else:
                    print("get public key first")
            
            elif choice == "4":
                break
            
            else:
                print("invalid choice")
    
    except KeyboardInterrupt:
        print("\ninterrupted, exiting")


if __name__ == "__main__":
    main()
