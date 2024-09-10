from test.test_findspam import test_findspam
import sys

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <input_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    with open(input_file, 'r') as f:
        input_string = f.read()
    test_findspam("DOS Prompt Issues", input_string, 'afx123', 'stackoverflow.com', True, True, True)