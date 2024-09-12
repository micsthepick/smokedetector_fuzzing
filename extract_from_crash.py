import atheris
import sys

def extract_string_from_file(filename):
    with open(filename, 'rb') as f:
        data = f.read()

    if len(data) < 3:
        return

    fdp = atheris.FuzzedDataProvider(data)
    string = fdp.ConsumeUnicode(len(data))  # Adjust as needed

    return string.encode('utf-8','ignore').decode("utf-8")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python script.py <input_file> <output_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    s = extract_string_from_file(input_file)

    with open(f"{output_file}", 'w') as f:
        f.write(s)
