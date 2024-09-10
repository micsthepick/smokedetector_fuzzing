import atheris
import sys

def extract_string_from_file(filename):
    with open(filename, 'rb') as f:
        data = f.read()

    if len(data) < 3:
        return

    fdp = atheris.FuzzedDataProvider(data)
    string = fdp.ConsumeUnicode(len(data))  # Adjust as needed

    return string

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <input_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    s = extract_string_from_file(input_file)

    with open(f"{'/'.join(input_file.split('/')[:-1])}/teststring-{input_file.split('/')[-1]}", 'w') as f:
        f.write(s)
