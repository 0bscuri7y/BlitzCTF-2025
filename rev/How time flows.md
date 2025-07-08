# How time flows

pretty basic program flow just gave context to gpt and told it to write a solve script but particularly in c because its easier to replicate the same rand function that way

code:- 

```c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void rc4_ksa(uint8_t s[256], uint8_t key[256]) {
    for (int i = 0; i < 256; i++)
        s[i] = i;

    uint32_t j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + s[i] + key[i]) % 256;
        uint8_t tmp = s[i];
        s[i] = s[j];
        s[j] = tmp;
    }
}

void rc4_prga(uint8_t s[256], uint8_t *keystream, size_t length) {
    int i = 0, j = 0;
    for (size_t k = 0; k < length; k++) {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;
        uint8_t tmp = s[i];
        s[i] = s[j];
        s[j] = tmp;
        keystream[k] = s[(s[i] + s[j]) % 256];
    }
}

int main() {
    FILE *f = fopen("flag.txt.enc", "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    if (fsize <= 0 || fsize > 65536) {
        fprintf(stderr, "[!] Invalid file size: %ld\n", fsize);
        fclose(f);
        return 1;
    }
    rewind(f);

    uint8_t *cipher = malloc(fsize);
    if (!cipher) {
        fprintf(stderr, "[!] Failed to allocate cipher buffer\n");
        fclose(f);
        return 1;
    }
    fread(cipher, 1, fsize, f);
    fclose(f);

    time_t now = time(NULL);
    int max_delta = 864000; // try 24 hours into the past

    for (int delta = 0; delta < max_delta; delta++) {
        srand((unsigned)(now - delta));
        uint8_t key[256];
        for (int i = 0; i < 256; i++) {
            key[i] = rand() & 0xff;
        }

        uint8_t s[256];
        rc4_ksa(s, key);

        uint8_t *keystream = malloc(fsize);
        uint8_t *s_copy = malloc(256);
        if (!keystream || !s_copy) {
            fprintf(stderr, "[!] Memory allocation failed for iteration %d\n", delta);
            free(keystream);
            free(s_copy);
            continue;
        }
        memcpy(s_copy, s, 256);
        rc4_prga(s_copy, keystream, fsize);
        free(s_copy);

        uint8_t *plain = malloc(fsize);
        if (!plain) {
            fprintf(stderr, "[!] Memory allocation failed for plaintext\n");
            free(keystream);
            continue;
        }
        for (int i = 0; i < fsize; i++)
            plain[i] = cipher[i] ^ keystream[i];

        if (memcmp(plain, "Blitz{", 6) == 0) {
            printf("[+] Found! Timestamp = %ld\n", now - delta);
            fwrite(plain, 1, fsize, stdout);
            printf("\n");
            free(plain);
            free(keystream);
            break;
        }
        free(plain);
        free(keystream);
    }
    free(cipher);
    return 0;
}

```

Final Flag

```python
./crack
[+] Found! Timestamp = 1751692692
Blitz{71m3_5ur3_fl0w5_f457_l1k3_4_r1v3r_50m371m35}
```