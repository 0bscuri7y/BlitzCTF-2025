# Chambers of Secrets

looking at hex view we can see there are magic bytes for a jpg file

so change extension to .jpg we see a page from a book (i think its harry potter?) but yeah

we can also extract a zip from the file using binwalk which we need to crack

my solve was to get the hash of the zip file then i just ran it against many wordlists i have and it matched **exchange** which we later saw was also 1 word in the page that was given to us

[https://lastchamberofsecrect.com/url-decode/base?galf=QmxpdHp7aDFkZDNuXzFuXzdoM19kMzNwX3hEfQ%3D%3D](https://lastchamberofsecrect.com/url-decode/base?galf=QmxpdHp7aDFkZDNuXzFuXzdoM19kMzNwX3hEfQ%3D%3D)

we see this in the extracted txt

decoding that base64 gives us the flag

Blitz{h1dd3n_1n_7h3_d33p_xD}