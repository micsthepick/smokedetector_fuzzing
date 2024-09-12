import sys
import os
from multiprocessing import Pool
from test.test_findspam import Post, FindSpam

def process_file(input_file, input_dir, id):
    """Worker function to process each file."""
    with open(f'{input_dir}/{input_file}', 'r') as f:
        input_string = f.read()
    
    try:
        post = Post(api_response={'title': input_file, 'body': input_string,
                              'owner': {'display_name': 'afx123', 'reputation': 1, 'link': ''},
                              'site': 'stackoverflow.com', 'question_id': str(id+1), 'IsAnswer': True,
                              'BodyIsSummary': True, 'score': 0})
        full_result = FindSpam.test_post(post)
        print(f'match? {full_result[0]}')
    except AssertionError:
        pass  # Handle or log failures if necessary

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <input_dir>")
        sys.exit(1)

    input_dir = sys.argv[1]

    # Get the list of files in the input directory
    input_files = os.listdir(input_dir)

    # Create a multiprocessing Pool
    with Pool(6) as pool:
        # Map the process_file function to each input file
        pool.starmap(process_file, [(input_file, input_dir, i) for i, input_file in enumerate(input_files)])
