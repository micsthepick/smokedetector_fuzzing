import atheris
import sys

MAXPOSTLEN = 28000
# 30 000 according to meta/q/176445

def extract_string_from_file(filename):
    with open(filename, 'rb') as f:
        data = f.read()

    if len(data) < 8:
        return

    fdp = atheris.FuzzedDataProvider(data)
    split1 = fdp.ConsumeUInt(2)
    split2 = fdp.ConsumeUInt(2)
    string = fdp.ConsumeUnicodeNoSurrogates(MAXPOSTLEN)

    string = ''.join(c for c in string if c not in {'\0', '\r', '\n'} and (ord(c) < 44032 or ord(c) >= 57344))

    mystringlen = len(string)

    split1 %= (mystringlen + 1)

    split2 %= mystringlen

    split2 = (split1 + split2 + 1) % (mystringlen + 1)

    if split2 < split1:
        split2, split1 = split1, split2

    lhs, mid, rhs = string[:split1], string[split1:split2], string[split2:]

    maxpump = (MAXPOSTLEN - (len(lhs) + len(rhs))) // len(mid)

    return lhs+mid*maxpump+rhs

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python script.py <input_file> <output_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    s = extract_string_from_file(input_file)

    with open(f"{output_file}", 'w') as f:
        f.write(s)
