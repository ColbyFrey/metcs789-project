from blum_blum_shub import BlumBlumShub
import rsa_a
import rsa_b
import pollard_rho
from rsa_operations import mod_inverse
import math 

class User:
    def __init__(self, int_size_bits: int):
        self.int_size_bits = int_size_bits
        self.bbs = BlumBlumShub(int_size_bits)
        self.p = 0
        self.q = 0 
        self.e = 65537  # common choice for e
        
    @property
    def n(self):
        return self.p * self.q
    
    @property
    def phi(self):
        return (self.p - 1) * (self.q - 1)
    
    @property
    def d(self):
        return mod_inverse(self.e, self.phi)
    
    def generate_rsa_keys(self):
        self.p = self.bbs.random_prime_from_bbs(self.int_size_bits)  # advance BBS state
        self.q = self.bbs.random_prime_from_bbs(self.int_size_bits)  # advance BBS state

    def print_private_keys(self):
        print("Private Keys: Save these to a file somewhere !")
        print(f"p: {self.p}")
        print(f"q: {self.q}")
        print(f"phi: {self.phi}")
        print(f"d: {self.d}")
        
    def print_public_key(self):
        print(f"Public Key (n, e): ({self.n}, {self.e})")
        
    def set_keys(self, p: int, q: int):
        self.p = p
        self.q = q
    

    
keys = User(64)


m = rsa_b.decrypt_message(c, keys.n, keys.d)

def test_keygen():
    keys.generate_rsa_keys()
    keys.print_public_key()
    keys.print_private_keys()

    factor = pollard_rho.factor_pollard_p1(keys.n, 1000000000)  
    otherFactor = keys.n // factor if factor else None
    if factor:
        print(f"Found factor: {factor}")
        print(f"Other factor: {keys.n // factor}")
        print(f"Verification: {factor * (keys.n // factor) == keys.n}")
    else:
        print("No factor found")


def test_decrypt_hack(c,n):
    sqrt_n = math.floor(math.sqrt(n) / 2)
    factor = pollard_rho.factor_pollard_p1(n, sqrt_n)
    otherFactor = n // factor if factor else None
    if not factor:
        print("No factor found")
        return
    phi = (factor - 1) * (otherFactor - 1)
    d = mod_inverse(65537, phi)
    m = rsa_b.decrypt_message(c, n, d)
    print(f"HACKED: message: {m}")

def test_message():    
    c = rsa_a.encrypt_message(keys.n, keys.e)  # using common e=65537
    print(f"ciphertext: {c}")

    m = rsa_b.decrypt_message(c, keys.n, keys.d)

    factor_phi = (factor - 1) * (otherFactor - 1)
    d_from_factor = mod_inverse(keys.e, factor_phi)
    m2 = rsa_b.decrypt_message_with_crt(c, keys.p, keys.q,d_from_factor)
    print(f"decrypted message: {m}")
    print(f"decrypted message with CRT: {m2}")

test_decrypt_hack(c,keys.n)