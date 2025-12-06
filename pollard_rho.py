import math


def factor_pollard_p1(n: int, B: int) -> int:
    a = 2
    j = 2
    while j <= B:
        
        a = pow(a,j,n)
        
        d  = math.gcd(a - 1, n)
        if 1 < d < n:
            return d
        j += 1
    return None

