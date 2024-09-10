#!/usr/bin/python
import atheris

## hook on regex ops
#atheris.enabled_hooks.add("RegEx")

with atheris.instrument_imports():
    import regex
    import sys

from globalvars import GlobalVars

from helpers import get_bookended_keyword_regex_text_from_entries
from findspam import URL_REGEX, REPEATED_CHARACTER_RATIO, city_list

MONOLITHIC = regex.compile(get_bookended_keyword_regex_text_from_entries(GlobalVars.watched_keywords.keys()), regex.UNICODE, city=city_list, ignore_unused=True)

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
    estimate = max(MONOLITHIC.scanner(string).bench()[1:])
    if estimate >= (1 << 20):
        raise ValueError(f'BOOM! [[[{string!r}]]] !BOOM')
    for i in reversed(range(1 << (20-13))):
        if estimate >= (i << 13):
            break

def TestAllWatchedKeywords(data: bytes):
    # Check each REGEX one by one, recording how long data takes
    # find out which took the longest, and print it

    if len(data) < 1:
        return

    fdp = atheris.FuzzedDataProvider(data)

    string = fdp.ConsumeUnicode(len(data))

    if len({'\0', '\r', '\n'} & set(string)) > 0:
        return

    if has_few_characters(string)[0]:
        return
    
    if has_repeating_characters(string)[0]:
        return

    runbench(string)
    
atheris.Setup(sys.argv, TestAllWatchedKeywords)
atheris.Fuzz()

