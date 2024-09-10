import atheris
import sys

def extract_string_from_file(filename):
    with open(filename, 'rb') as f:
        data = f.read()

    if len(data) < 3:
        return

    fdp = atheris.FuzzedDataProvider(data)
    string = fdp.ConsumeUnicode(len(data) - 2)  # Adjust as needed

    print(f'Extracted string: {string!r}')

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <input_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    extract_string_from_file(input_file)
