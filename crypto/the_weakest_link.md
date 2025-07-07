## The Weakest Link

Pretty straightforward challenge. Make wordlist and run attack

### Phone password
Only 4 digits, ran sha1 from 0000-9999, failed. then tried hash idenitifier, and it suggested it could be sha1 of sha1 as well, so I ran a simple bruteforce script with double sha1 in python and got 0698 as a hit.


### computer password
Now, for next challenge, used an online wordlist generator and generated full wordlist. but md5 bruteforce failed. Previous phone password told that it doens't necessarily has to be md5 only. so again, put it in hash identifier, took all possible hash formats, and made a short python script that tried all. Got a hit at md4 (UTF-16LE). Password was chinto1998


### Instagram password
Next had to be bcyrpt hash. Used the same wordlist, just added a filter of 6 character long and [a-zA-Z0-9]. But it failed, maybe cuz it had mostly >8 length passwords. So I have chatgpt all the info about Rahul, and asked it to create possible password wordlist given the length and character set. It gave ~45 passwords, and 1 was successful match - "Neha06"

### Blockchain Wallet
This one seemed like a sha256. wordlist failed. So I tried to gerenate wordlist using my own logic. First I saw that out of given information, only his own name, i.e Rahul Sharma was unused. So I for once, assumed password had to include Rahul or Sharma.

#### Try 1
I made these as potential names to be used - base_names=["Rahul", "Sharma", "R@hul", "Sh@rma", "Sharm@", "Sh@rm@"]. Then I thought password might start with a symbol, so i tried bruteforce in this format -<$ or @><base_name><remaining could be numbers or symbols>
But this failed.

#### Try 2
Using same base names, i though maybe there was no symbol in start. So i modified the format - <base_name><remaining could be numbers or symbols>
This worked, and I got a match with "R@hul98"

Script for bruteforcing final hash
```python
import hashlib
from itertools import product

# Given hash and salt
target_hash = "c53120130d9cf35015deec2e6452c791d29d3556cfd01a2e543165aca00e2192"
salt = "BlitzHack"

# Pattern components
bases = ["R@hul", "Rahul", "Sharma", "Sh@rma", "Sharm@", "Sh@rm@"]
tail_chars = [str(d) for d in range(10)] + ["$", "@"]

matches = []

for base in bases:
    # Determine required suffix length to make total length 7
    suffix_len = 7 - len(base)
    if suffix_len < 0:
        continue  # skip if base too long
    # Iterate over all possible suffix combinations
    for suffix in product(tail_chars, repeat=suffix_len):
        pwd = base + "".join(suffix)
        h = hashlib.sha256((salt + pwd).encode()).hexdigest()
        if h == target_hash:
            matches.append(pwd)

# Display results
if matches:
    print("Match(es) found:", matches)
else:
    print("No matches found with the updated pattern.")

```