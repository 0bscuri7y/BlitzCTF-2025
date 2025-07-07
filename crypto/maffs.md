# Maffs

> How much of maffs do you know?

**Try 1**
assuming there are 34 chars in the flag and each file represent a single character i started by trying to use np.polyfit to get coefficients for the the 10 (x,y) pairs given , that yielded some results that looked to be right, and wasted much time there trying to find a general equation for coefficients to char

**Try 2**
after not having much luck with first approach , i tried asking llms for analysis and help , which is where i found newton divided difference,
trying to use that against f0.txt , we got B , so decoding all the files , we got the flag.

**Flag**: Blitz{C4lcu1us_G0eS_Brrrrrrrrr!!!}

```python
import numpy as np

def factorial(n):
    if n == 0:
        return 1
    result = 1
    for i in range(1, n+1):
        result *= i
    return result

def newton_divided_difference(x, y):
    n = len(x)
    F = np.zeros((n, n))
    F[:,0] = y
    
    for i in range(1, n):
        for j in range(n - i):
            F[j,i] = (F[j+1, i-1] - F[j, i-1]) / (x[j+i] - x[j])
    
    return F[0]

def get_ascii_from_file(filename):
    data = np.loadtxt(filename)
    x = data[:, 0]
    y = data[:, 1]
    
    # Check if sorted, Newton's method requires sorted x? Not necessarily, but often numerically stable if sorted.
    # We'll sort the points by x
    idx = np.argsort(x)
    x_sorted = x[idx]
    y_sorted = y[idx]
    
    # Compute divided differences
    dd = newton_divided_difference(x_sorted, y_sorted)
    
    # Find the highest non-zero order (considering floating point tolerance)
    tol = 1e-5
    k = len(dd) - 1
    while k >= 0:
        if abs(dd[k]) > tol:
            break
        k -= 1
    
    if k < 0:
        return 0  # Default if no non-zero found, though unlikely
    
    # Multiply by factorial(k) and round to integer
    ascii_val = round(dd[k] * factorial(k))
    return ascii_val

flag_chars = []
for i in range(34):
    filename = f'f{i}.txt'
    ascii_val = get_ascii_from_file(filename)
    flag_chars.append(chr(ascii_val))

flag = ''.join(flag_chars)
print(flag)
```
maffs