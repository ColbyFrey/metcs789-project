from blum_blum_shub import BlumBlumShub
import rsa_a


class User:
    def __init__(self, int_size_bits: int):
        self.int_size_bits = int_size_bits
        self.bbs = BlumBlumShub(int_size_bits)
        self.p = 0
        self.q = 0  
        
    @property
    def n(self):
        return self.p * self.q
    
    @property
    def phi(self):
        return (self.p - 1) * (self.q - 1)
    
    def generate_rsa_keys(self):
        self.p = self.bbs.random_int_from_bbs(self.int_size_bits)  # advance BBS state
        self.q = self.bbs.random_int_from_bbs(self.int_size_bits)  # advance BBS state

    def debug_print_keys(self):
        print(f"p: {self.p}")
        print(f"q: {self.q}")
        print(f"n: {self.n}")
        
    
keys = User(64)
keys.generate_rsa_keys()
keys.debug_print_keys()

c = rsa_a.encrypt_message(keys.n, 65537)  # using common e=65537
print(f"ciphertext: {c}")