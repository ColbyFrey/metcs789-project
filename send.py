from blum_blum_shub import BlumBlumShub
import rsa_a
import pollard_rho

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
    
    def generate_rsa_keys(self):
        self.p = self.bbs.random_prime_from_bbs(self.int_size_bits)  # advance BBS state
        self.q = self.bbs.random_prime_from_bbs(self.int_size_bits)  # advance BBS state

    def print_private_keys(self):
        print("Private Keys: Save these to a file somewhere !")
        print(f"p: {self.p}")
        print(f"q: {self.q}")
        print(f"n: {self.n}")
        print(f"phi: {self.phi}")
        
    def print_public_key(self):
        print(f"Public Key (n, e): ({self.n}, {self.e})")
        
    def set_keys(self, p: int, q: int):
        self.p = p
        self.q = q
    

    
keys = User(32)
keys.generate_rsa_keys()
keys.print_public_key()
keys.print_private_keys()

factor = pollard_rho.factor_pollard_p1(keys.n, 10000000)  
if factor:
    print(f"Found factor: {factor}")
    print(f"Other factor: {keys.n // factor}")
    print(f"Verification: {factor * (keys.n // factor) == keys.n}")
else:
    print("No factor found")
    
#c = rsa_a.encrypt_messag   e(keys.n, 65537)  # using common e=65537
#print(f"ciphertext: {c}")