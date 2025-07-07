### Jail

After logging in, first looked where the flag is, found it in /root/root.txt. No read permissions. 

Ran `sudo -l`. We could run md5sum, but that was useless. So without looking much ahead, I just ran linpeas.sh, and in the results, it showed that /usr/bin/base64 had suid bit set, i.e., we could could run it as root without sudo. So i just ran `base64 /root/root.txt` and got the flag.