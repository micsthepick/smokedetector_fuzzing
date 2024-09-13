#!/usr/bin/python
import atheris
import signal
import os
import pickle

with atheris.instrument_imports():
    import regex
    import sys


def get_file_timestamp(file_path):
    try:
        return os.path.getmtime(file_path)
    except OSError:
        raise FileNotFoundError(f"File not found: {file_path}")

def load_or_compile_regex(txt_file_path, pickle_dir):
    txt_file_timestamp = get_file_timestamp(txt_file_path)
    pickle_filename = f"watched_keywords_regex_{int(txt_file_timestamp)}.pkl"
    pickle_path = os.path.join(pickle_dir, pickle_filename)

    if os.path.exists(pickle_path):
        with open(pickle_path, 'rb') as pickle_file:
            URL_REGEX, REPEATED_CHARACTER_RATIO, compiled_regex = pickle.load(pickle_file)
            print(f"Loaded regex for {txt_file_path} from pickle!")
    else:
        from globalvars import GlobalVars
        from helpers import get_bookended_keyword_regex_text_from_entries
        from findspam import URL_REGEX, REPEATED_CHARACTER_RATIO, city_list
        keyword_regex = get_bookended_keyword_regex_text_from_entries(GlobalVars.watched_keywords.keys())
        compiled_regex = regex.compile(keyword_regex, regex.UNICODE, city=city_list)

        with open(pickle_path, 'wb') as pickle_file:
            pickle.dump([URL_REGEX, REPEATED_CHARACTER_RATIO, compiled_regex], pickle_file)
            print(f"Saved regex for {txt_file_path} to pickle!")


    return [URL_REGEX, REPEATED_CHARACTER_RATIO, compiled_regex]

txt_file = "watched_keywords.txt"
pickle_directory = "./pickles"

if not os.path.exists(pickle_directory):
    os.makedirs(pickle_directory)

URL_REGEX, REPEATED_CHARACTER_RATIO, MONOLITHIC = load_or_compile_regex(txt_file, pickle_directory)

@atheris.instrument_func
def has_few_characters(s):
    uniques = len(set(s) - {"\n", "\t"})
    length = len(s)
    thresholds = [  # LBound, UBound, MaxUnique
        (30, 36, 6), (36, 42, 7), (42, 48, 8), (48, 54, 9), (54, 60, 10),
        (60, 70, 11), (70, 80, 12), (80, 90, 13), (90, 100, 14), (100, 2**30, 15),
    ]
    if any([t[0] <= length < t[1] and uniques <= t[2] for t in thresholds]):
        return True, "Contains {} unique character{}".format(uniques, "s" if uniques >= 2 else "")
    return False, ""

@atheris.instrument_func
def has_repeating_characters(s):
    s = s.strip().replace("\u200B", "").replace("\u200C", "")  # Strip leading and trailing spaces
    if "\n\n" in s or "<code>" in s or "<pre>" in s:
        return False, ""
    s = URL_REGEX.sub("", s)  # Strip URLs for this check
    if not s:
        return False, ""
    # Don't detect a couple of common ways for people to try to include tables (reduces FP by ~20%).
    if regex.search(r"(?:(?:----+|====+)[+|]+){2}", s):
        return False, ""
    # matches = regex.compile(r"([^\s_.,?!=~*/0-9-])(\1{9,})", regex.UNICODE).findall(s)
    matches = regex.compile(r"([^\s\d_.])(\1{9,})", regex.UNICODE).findall(s)
    match = "".join(["".join(match) for match in matches])
    if len(match) / len(s) >= REPEATED_CHARACTER_RATIO:  # Repeating characters make up >= 20 percent
        return True, "{}".format(", ".join(
            ["{}*{}".format(repr(match[0]), len(''.join(match))) for match in matches]))
    return False, ""

@atheris.instrument_func
def runbench(string: str):
    for estimate in MONOLITHIC.scanner(string).bench()[1:]:
        if estimate >= (1 << 22):
            raise ValueError(f'BOOM! [[[{string!r}]]] !BOOM')
        ##for i in reversed(range(1, 1 << (20-13))):
        ##    if estimate >= (i << 16):
        ##        break
        # for loop doesn't work properly with atheris at this moment
        if estimate >= (63 << 16): break
        elif estimate >= (62 << 16): break
        elif estimate >= (61 << 16): break
        elif estimate >= (60 << 16): break
        elif estimate >= (59 << 16): break
        elif estimate >= (58 << 16): break
        elif estimate >= (57 << 16): break
        elif estimate >= (56 << 16): break
        elif estimate >= (55 << 16): break
        elif estimate >= (54 << 16): break
        elif estimate >= (53 << 16): break
        elif estimate >= (52 << 16): break
        elif estimate >= (51 << 16): break
        elif estimate >= (50 << 16): break
        elif estimate >= (49 << 16): break
        elif estimate >= (48 << 16): break
        elif estimate >= (47 << 16): break
        elif estimate >= (46 << 16): break
        elif estimate >= (45 << 16): break
        elif estimate >= (44 << 16): break
        elif estimate >= (43 << 16): break
        elif estimate >= (42 << 16): break
        elif estimate >= (41 << 16): break
        elif estimate >= (40 << 16): break
        elif estimate >= (39 << 16): break
        elif estimate >= (38 << 16): break
        elif estimate >= (37 << 16): break
        elif estimate >= (36 << 16): break
        elif estimate >= (35 << 16): break
        elif estimate >= (34 << 16): break
        elif estimate >= (33 << 16): break
        elif estimate >= (32 << 16): break
        elif estimate >= (31 << 16): break
        elif estimate >= (30 << 16): break
        elif estimate >= (29 << 16): break
        elif estimate >= (28 << 16): break
        elif estimate >= (27 << 16): break
        elif estimate >= (26 << 16): break
        elif estimate >= (25 << 16): break
        elif estimate >= (24 << 16): break
        elif estimate >= (23 << 16): break
        elif estimate >= (22 << 16): break
        elif estimate >= (21 << 16): break
        elif estimate >= (20 << 16): break
        elif estimate >= (19 << 16): break
        elif estimate >= (18 << 16): break
        elif estimate >= (17 << 16): break
        elif estimate >= (16 << 16): break
        elif estimate >= (15 << 16): break
        elif estimate >= (14 << 16): break
        elif estimate >= (13 << 16): break
        elif estimate >= (12 << 16): break
        elif estimate >= (11 << 16): break
        elif estimate >= (10 << 16): break
        elif estimate >= (9 << 16): break
        elif estimate >= (8 << 16): break
        elif estimate >= (7 << 16): break
        elif estimate >= (6 << 16): break
        elif estimate >= (5 << 16): break
        elif estimate >= (4 << 16): break
        elif estimate >= (3 << 16): break
        elif estimate >= (2 << 16): break
        elif estimate >= (1 << 16): break

@atheris.instrument_func
def TestAllWatchedKeywords(data: bytes):
    # Check each REGEX one by one, recording how long data takes
    # find out which took the longest, and print it

    if len(data) < 1:
        return

    fdp = atheris.FuzzedDataProvider(data)

    string = fdp.ConsumeUnicode(len(data))

    if len({'\0', '\r', '\n'} & set(string)) > 0:
        return

    # hangul syllables and surrogates not allowed
    # (not sure about the hangul)
    for c in string:
        if 44032 <= ord(c) < 57344:
            return

    if has_few_characters(string)[0]:
        return
    
    if has_repeating_characters(string)[0]:
        return

    runbench(string)

def stop_fuzzing(signum, frame):
    print("\nGracefully stopping fuzzing...")
    sys.exit(0)  # Exit the program without error

if __name__ == '__main__':
    signal.signal(signal.SIGINT, stop_fuzzing)
    atheris.Setup(sys.argv, TestAllWatchedKeywords)
    atheris.Fuzz()