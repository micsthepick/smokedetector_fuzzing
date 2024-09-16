#!/usr/bin/python
import math
import atheris
import os
import pickle
import numpy as np
from regress_exponential import get_coeffs

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

MAXPOSTLEN = 28000
# 30 000 according to meta/q/176445

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
def runbench(lhs: str, mid: str, rhs: str):
    maxpump = (MAXPOSTLEN - (len(lhs) + len(rhs))) // len(mid)
    if maxpump < 40:
        return -1
    x_values = np.array(range(1, 40))
    y_values = []
    for pump in x_values:
        string = lhs + mid*pump + rhs
        y_values.append(MONOLITHIC.scanner(string).bench()[-1])
    # fit lin/quad/cubic
    poly_coeffs = np.polyfit(x_values, y_values, 3)
    for i in range(len(poly_coeffs)):
        if poly_coeffs[i] < 0:
                poly_coeffs[i] = 0
        else:
            break
    y_poly = np.polyval(poly_coeffs, x_values)
    ssq_poly = np.sum((y_poly - y_values) ** 2)
    e_a, e_b, e_c = get_coeffs(x_values, y_values)
    e_b = min(3, e_b)
    y_exp = e_a * np.exp(e_b * x_values) + e_c
    ssq_exp = np.sum((y_poly - y_exp) ** 2)
    print(ssq_exp, ssq_poly)
    if ssq_exp < ssq_poly:
        estimate = e_a * np.exp(e_b * maxpump) + e_c
    else:
        estimate = np.polyval(poly_coeffs, maxpump)
    estimate = np.log(estimate)
    if estimate >= 32:
        raise ValueError(f'BOOM! <{estimate}> [[[{lhs!r}][{mid!r}][{rhs!r}]]] !BOOM')
    ##for i in reversed(range(1, 1 << (20-13))):
    ##    if estimate >= (i):
    ##        return estimate
    # for loop doesn't work properly with atheris at this moment
    if estimate >= (31): return estimate
    if estimate >= (30): return estimate
    if estimate >= (29): return estimate
    if estimate >= (28): return estimate
    if estimate >= (27): return estimate
    if estimate >= (26): return estimate
    if estimate >= (25): return estimate
    if estimate >= (24): return estimate
    if estimate >= (23): return estimate
    if estimate >= (22): return estimate
    if estimate >= (21): return estimate
    if estimate >= (20): return estimate
    if estimate >= (19): return estimate
    elif estimate >= (18): return estimate
    elif estimate >= (17): return estimate
    elif estimate >= (16): return estimate
    elif estimate >= (15): return estimate
    elif estimate >= (14): return estimate
    elif estimate >= (13): return estimate
    elif estimate >= (12): return estimate
    elif estimate >= (11): return estimate
    elif estimate >= (10): return estimate
    elif estimate >= (9): return estimate
    elif estimate >= (8): return estimate
    elif estimate >= (7): return estimate
    elif estimate >= (6): return estimate
    elif estimate >= (5): return estimate
    elif estimate >= (4): return estimate
    elif estimate >= (3): return estimate
    elif estimate >= (2): return estimate
    elif estimate >= (1): return estimate

@atheris.instrument_func
def TestAllWatchedKeywords(data: bytes):
    # Check each REGEX one by one, recording how long data takes
    # find out which took the longest, and print it

    if len(data) < 8:
        return

    fdp = atheris.FuzzedDataProvider(data)

    split1 = fdp.ConsumeUInt(2)
    split2 = fdp.ConsumeUInt(2)

    string = fdp.ConsumeUnicodeNoSurrogates(MAXPOSTLEN)

    string = ''.join(c for c in string if c not in {'\0', '\r', '\n', '\x1e'} and (ord(c) < 44032 or ord(c) >= 57344) and (ord(c) < 0x7f or ord(c) > 0x9f) and ord(c) >= 0x20)

    # hangul syllables and surrogates not allowed
    # (not sure for reasoning about the hangul)
    mystringlen = len(string)

    if mystringlen < 3:
        return

#    if has_few_characters(string)[0]:
#        return

#    if has_repeating_characters(string)[0]:
#        return

    split1 %= (mystringlen + 1)

    split2 %= mystringlen

    split2 = (split1 + split2 + 1) % (mystringlen + 1)

    if split2 < split1:
        split2, split1 = split1, split2

    string_args = string[:split1], string[split1:split2], string[split2:]

    runbench(*string_args)

if __name__ == '__main__':
    atheris.Setup(sys.argv, TestAllWatchedKeywords)
    atheris.Fuzz()