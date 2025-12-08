import math
import random

SMALL_PRIMES = [3, 5, 7, 11, 13, 17, 19, 23,
                29, 31, 37, 41, 43, 47, 53, 59]


class BlumBlumShub:
    def __init__(self, int_size_bits: int):
        """
        Initialize an instance with BBS parameters:
        - self.p, self.q: Blum primes
        - self.n: modulus = p * q
        - self.seed: initial seed value r used to create x0 = r^2 mod n
        """
        self.bits = int_size_bits
        self.p, self.q, self.n, self.seed = self.bbs_keygen(int_size_bits)
        
    # --------------------------
    # Miller-Rabin
    # --------------------------
    @staticmethod
    def miller_rabin(n: int, testIterations: int = 8) -> bool:
        if n <= 1:
            return False
        if n <= 3:
            return True
        if n % 2 == 0:
            return False  # even and > 2
        if n % 3 == 0:
            return False  # divisible by 3

        d = n - 1  # because 2^r * d
        r = 0

        while d % 2 == 0:  # find r and d where d is odd
            d //= 2
            r += 1

        for _ in range(testIterations):
            a = random.randint(2, n - 2)  # pick a random 'a' in [2, n-2]
            x = pow(a, d, n)  # compute a^d % n

            if x == 1 or x == n - 1:  # pass
                continue

            for _ in range(r - 1):
                x = pow(x, 2, n)  # check if x^2 is n-1
                if x == n - 1:
                    break
            else:
                return False

        return True

    # --------------------------
    # Generate Blum prime
    # --------------------------
    @classmethod
    def generate_blum_prime(cls, bit_length: int) -> int:
        attempts = 0
        while True:
            attempts += 1
            if attempts % 1000 == 0:
                print(f"tried {attempts} candidates for {bit_length}-bit prime...")

            candidate = random.getrandbits(bit_length)
            candidate |= (1 << (bit_length - 1))  # ensure correct bit length by setting MSB
            candidate |= 3                        # force ≡ 3 (mod 4) by setting last two bits
            
            if candidate % 4 != 3:
                continue                

            if cls.miller_rabin(candidate):
                print(f"Generated {bit_length}-bit Blum prime {candidate} after {attempts} attempts")
                return candidate
            else:
                print(f"candidate {candidate} failed primality test")

    # --------------------------
    # BBS bit generator 
    # --------------------------
    def blum_blum_shub(self, iterations: int) -> list[int]:
        """
        Generate a sequence of bits using the instance's p, q, and seed.
        """
        p = self.p
        q = self.q
        seed = self.seed

        assert p % 4 == 3
        assert q % 4 == 3

        n = p * q

        if math.gcd(seed, n) != 1:
            raise ValueError("Seed must be coprime to n = p * q")

        x = pow(seed, 2, n)
        b = []

        numbers = []
        for _ in range(iterations):
            x = pow(x, 2, n)
            b.append(x % 2)
            numbers.append(x)

        self.seed = x  # update seed for next call
        return b

    # --------------------------
    # Random int from BBS bits 
    # --------------------------
    def random_prime_from_bbs(self, bit_length: int) -> int:
        """
        Build a random integer of exact 'bit_length' bits using the instance's parameters.
        """

        # Set the most significant bit to ensure correct bit length
        
        while True:
            bits = self.blum_blum_shub(bit_length)
            value = 1 << (bit_length - 1)

            # Fill remaining bits
            for i in range(bit_length - 1):
                value |= (bits[i] << i)
            
            value |= 1  # ensure odd
            
            # quick small prime filter
            if any(value % sp == 0 for sp in SMALL_PRIMES):
                continue
            
            if self.miller_rabin(value):
                return value

        return None

    # --------------------------
    # BBS Keygen (class-level, used in __init__)
    # --------------------------
    @classmethod
    def bbs_keygen(cls, bitSize: int):
        # pick p and q of about half the modulus size
        p_bits = math.floor(bitSize / 2)
        q_bits = bitSize - p_bits

        p = cls.generate_blum_prime(p_bits)
        q = cls.generate_blum_prime(q_bits)

        while q == p:  # ensure p and q are distinct
            q = cls.generate_blum_prime(q_bits)

        n = p * q

        # pick a random seed r coprime to n, and set x0 = r^2 mod n
        while True:
            r = random.randrange(2, n - 1)
            if math.gcd(r, n) == 1:
                break

        x0 = pow(r, 2, n)
        return p, q, n, x0
