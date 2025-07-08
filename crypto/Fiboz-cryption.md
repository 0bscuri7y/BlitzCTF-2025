# Fiboz-cryption

```python
#!/usr/bin/env python3
import sys
from functools import lru_cache

def collatz_steps(n):
    """
    Count the number of steps it takes for n to reach 1
    following the Collatz sequence.
    """
    s = 0
    while n != 1:
        n = n // 2 if n % 2 == 0 else 3 * n + 1
        s += 1
    return s

def fiboz(l, a=1, b=1):
    """
    Generate a Fibonacci-like sequence of length l,
    starting with seeds a and b.
    """
    R = [a, b]
    for _ in range(l - 2):
        R.append(R[-1] + R[-2])
    return R

def decrypt(ct, l, a, b):
    """
    Decrypt ciphertext ct using parameters (l, a, b).
    """
    # Build the custom Fibonacci-based keystream
    f = fiboz(l, a, b)
    # Cache Collatz counts for speed
    cache = lru_cache(maxsize=None)(collatz_steps)
    # Generate keystream bytes
    k = [cache(n) & 0xFF for n in f]

    # XOR ciphertext with keystream (repeating if needed)
    pt = bytes(ct[i] ^ k[i % len(k)] for i in range(len(ct)))
    return pt

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print(f"Usage: {sys.argv[0]} <cipherfile> <L> <A> <B>")
        sys.exit(1)

    fn, l_val, a_val, b_val = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
    ciphertext = open(fn, "rb").read()
    plaintext = decrypt(ciphertext, l_val, a_val, b_val)

    try:
        print(plaintext.decode('utf-8'))
    except UnicodeDecodeError:
        # Fallback: print raw bytes
        print(plaintext)
```