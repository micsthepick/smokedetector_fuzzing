import struct

with open('examples/aaa.example', 'wb') as f:
    f.write(struct.pack('2H3c5B', 1, 1, b'a', b'a', b'a', 0, 0, 0, 0, 0))


with open('examples/aaabbaaa.example', 'wb') as f:
    f.write(struct.pack('2H8c', 3, 2, b'a', b'a', b'a', b'b', b'b', b'a', b'a', b'a'))