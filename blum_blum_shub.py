import math
import random

def isPrime(num: int) -> bool:
    if num <= 1:
        return False
    for i in range(2, int(num**0.5) + 1):
        if num % i == 0:
            return False
    return True

#Generate a sequence of bits using Blum Blum Shub algorithm
def blum_blum_shub(p: int, q: int, seed: int, iterations: int) -> list[int]:
    assert p % 4 == 3 
    assert q % 4 == 3   
    n = p * q
    
    if(math.gcd(seed, n) != 1):
        raise ValueError("Seed must be coprime to n = p * q")
    
    x = pow(seed, 2, n)
    b = []
    
    numbers = []
    for _ in range(iterations):
        x =  pow(x, 2, n)
        b.append(x % 2) 
        numbers.append(x)
        
    return b

#Using array of bits from blum_blum_shub method to build a random integer
def random_int_from_bbs(p: int, q: int, seed: int, bit_length: int) -> int:
    """
    Build a random integer of exact 'bit_length' bits
    """
    bits = blum_blum_shub(p, q, seed, bit_length)

    # Convert bit array to integer
    # Set the most significant bit to ensure correct bit length
    value = 1 << (bit_length - 1)

    # Fill remaining bits and ensure it is od
    for i in range(bit_length - 1):
        value |= (bits[i] << i)
    return value

# Miller-Rabin Primality Test
# if n is prime then a^(n-1) ≡ 1 (mod n)
# for n, n-1 = 2^r * d
def miller_rabin(n: int, testIterations: int = 10) -> bool:
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False  # even and > 2
    
    d = n - 1 # because 2r * d
    r = 0 

    while d % 2 == 0: # find r and d  where d is odd
        d = math.floor(d / 2)
        r += 1

    for _ in range(testIterations):
        a = random.randint(2, n - 2) #pick a random 'a' in [2, n-2]
        x = pow(a, d, n) # compute a^d % n

        if x == 1 or x == n - 1: # pass
            continue

        for _ in range(r - 1): 
            x = pow(x, 2, n)  # check if the square of x is n-1
            
            if x == n - 1: # 
                break
        else:
            return False

    return True

def bbs_prime(bit_length: int, p: int, q: int, seed: int) -> int:
    """
    generate random number, test with Miller–Rabin,
    and return a probable prime.
    """
    while True:
        candidate = random_int_from_bbs(p, q, seed, bit_length)
        if miller_rabin(candidate):
            return candidate
        # change the seed slightly 
        seed += 1
        
#print(bbs_prime(256, 30000000091, 40000000003, 4882516702))  # Example usage

print(miller_rabin(101))  # Example usage
