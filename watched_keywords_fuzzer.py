#!/usr/bin/python
import atheris

## hook on regex ops
#atheris.enabled_hooks.add("RegEx")

with atheris.instrument_imports():
    import time
    import regex as re
    import sys

from globalvars import GlobalVars
from blacklists import load_blacklists

from findspam import city_list, regex_compile_no_cache, URL_REGEX, REPEATED_CHARACTER_RATIO


load_blacklists()

KWDS = GlobalVars.watched_keywords.keys()

print(f'loaded {len(KWDS)} KWDS')

REGEXES = [regex_compile_no_cache(kw, re.UNICODE, city=city_list, ignore_unused=True) for kw in KWDS if len(set(kw) - set('qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM./\\'))]

print(f'rejected {len(KWDS)-len(REGEXES)} KWDS (too simple) and left with {len(REGEXES)}')

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
    if re.search(r"(?:(?:----+|====+)[+|]+){2}", s):
        return False, ""
    # matches = regex.compile(r"([^\s_.,?!=~*/0-9-])(\1{9,})", regex.UNICODE).findall(s)
    matches = re.compile(r"([^\s\d_.])(\1{9,})", re.UNICODE).findall(s)
    match = "".join(["".join(match) for match in matches])
    if len(match) / len(s) >= REPEATED_CHARACTER_RATIO:  # Repeating characters make up >= 20 percent
        return True, "{}".format(", ".join(
            ["{}*{}".format(repr(match[0]), len(''.join(match))) for match in matches]))
    return False, ""

@atheris.instrument_func
def TestAllWatchedKeywords(data: bytes):
    global maxes
    # Check each REGEX one by one, recording how long data takes
    # find out which took the longest, and print it

    if len(data) < 2:
        return

    if len([v for v in data if v == 0]) > 0:
        return

    fdp = atheris.FuzzedDataProvider(data)

    string = fdp.ConsumeUnicode(len(data) - 2)

    if has_few_characters(string)[0]:
        return
    
    if has_repeating_characters(string)[0]:
        return

    index = fdp.ConsumeIntInRange(0, len(REGEXES)-1)

    ##fuzz_me(index, string)
    min_match_num = None
    for i in range(len(REGEXES)):
        stack_sizes = REGEXES[index].bench(string)
        max_num = max(stack_sizes)
        min_match_num = max_num if min_match_num is None else max_num if max_num < min_match_num else min_match_num 
    if min_match_num >= (1 << 10):
        for i in range(16, 9):
            if ((1<<i)&min_match_num):
                print(i)
                break
    if min_match_num >= (1 << 17):
        raise ValueError(repr(f'BOOM! [[[{string}]]] !BOOM'))

atheris.Setup(sys.argv, TestAllWatchedKeywords)
atheris.Fuzz()
