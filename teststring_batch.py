from test.test_findspam import test_findspam
import sys
import os

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <input_dir>")
        sys.exit(1)

    input_dir = sys.argv[1]
    for input_file in os.listdir(input_dir):
        with open(f'{input_dir}/{input_file}', 'r') as f:
            input_string = f.read()
        try:
            test_findspam(input_file, input_string, 'afx123', 'stackoverflow.com', True, True, True)
        except AssertionError:
            pass
