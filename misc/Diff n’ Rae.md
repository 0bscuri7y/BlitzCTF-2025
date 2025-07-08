# Diff n’ Rae

we are given 2 jpegs so just taking their differences and printing it out

```python
cmp -l Tate_McRae_1.jpg Tate_McRae_2.jpg | awk '{print $2, $3}'
121 5
155 5
170 5
26 160
25 144
26 110
33 160
27 67
132 0
104 0
106 0
155 0
0 122
0 154
0 70
0 170
125 0
61 0
20 71
2 61
22 116
124 0
116 0
155 0
0 144
0 125
0 170
0 71
```

this prints out the difference in bytes and those values also look like bytes so lets take the ones that are valid and printable and conevrt them to ascii we get

```python
QmxpdHp7ZDFmRl8xU191NTNmdUx9
```

this is base64 and decoding this gives us the flag

```python
Blitz{d1fF_1S_u53fuL} #cmp is useful too :p
```