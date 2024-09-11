#!/usr/bin/python
import atheris

with atheris.instrument_imports():
    import regex
    import sys

from globalvars import GlobalVars

from helpers import get_bookended_keyword_regex_text_from_entries
from findspam import URL_REGEX, REPEATED_CHARACTER_RATIO, city_list

MONOLITHIC = regex.compile(get_bookended_keyword_regex_text_from_entries(GlobalVars.watched_keywords.keys()), regex.UNICODE, city=city_list, ignore_unused=True)

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
        if estimate >= (1 << 20):
            raise ValueError(f'BOOM! [[[{string!r}]]] !BOOM')
        ##for i in reversed(range(1, 1 << (20-13))):
        ##    if estimate >= (i << 13):
        ##        break
        # for loop doesn't work properly with atheris at this moment
        if estimate >= (127 << 13): break
        elif estimate >= (126 << 13): break
        elif estimate >= (125 << 13): break
        elif estimate >= (124 << 13): break
        elif estimate >= (123 << 13): break
        elif estimate >= (122 << 13): break
        elif estimate >= (121 << 13): break
        elif estimate >= (120 << 13): break
        elif estimate >= (119 << 13): break
        elif estimate >= (118 << 13): break
        elif estimate >= (117 << 13): break
        elif estimate >= (116 << 13): break
        elif estimate >= (115 << 13): break
        elif estimate >= (114 << 13): break
        elif estimate >= (113 << 13): break
        elif estimate >= (112 << 13): break
        elif estimate >= (111 << 13): break
        elif estimate >= (110 << 13): break
        elif estimate >= (109 << 13): break
        elif estimate >= (108 << 13): break
        elif estimate >= (107 << 13): break
        elif estimate >= (106 << 13): break
        elif estimate >= (105 << 13): break
        elif estimate >= (104 << 13): break
        elif estimate >= (103 << 13): break
        elif estimate >= (102 << 13): break
        elif estimate >= (101 << 13): break
        elif estimate >= (100 << 13): break
        elif estimate >= (99 << 13): break
        elif estimate >= (98 << 13): break
        elif estimate >= (97 << 13): break
        elif estimate >= (96 << 13): break
        elif estimate >= (95 << 13): break
        elif estimate >= (94 << 13): break
        elif estimate >= (93 << 13): break
        elif estimate >= (92 << 13): break
        elif estimate >= (91 << 13): break
        elif estimate >= (90 << 13): break
        elif estimate >= (89 << 13): break
        elif estimate >= (88 << 13): break
        elif estimate >= (87 << 13): break
        elif estimate >= (86 << 13): break
        elif estimate >= (85 << 13): break
        elif estimate >= (84 << 13): break
        elif estimate >= (83 << 13): break
        elif estimate >= (82 << 13): break
        elif estimate >= (81 << 13): break
        elif estimate >= (80 << 13): break
        elif estimate >= (79 << 13): break
        elif estimate >= (78 << 13): break
        elif estimate >= (77 << 13): break
        elif estimate >= (76 << 13): break
        elif estimate >= (75 << 13): break
        elif estimate >= (74 << 13): break
        elif estimate >= (73 << 13): break
        elif estimate >= (72 << 13): break
        elif estimate >= (71 << 13): break
        elif estimate >= (70 << 13): break
        elif estimate >= (69 << 13): break
        elif estimate >= (68 << 13): break
        elif estimate >= (67 << 13): break
        elif estimate >= (66 << 13): break
        elif estimate >= (65 << 13): break
        elif estimate >= (64 << 13): break
        elif estimate >= (63 << 13): break
        elif estimate >= (62 << 13): break
        elif estimate >= (61 << 13): break
        elif estimate >= (60 << 13): break
        elif estimate >= (59 << 13): break
        elif estimate >= (58 << 13): break
        elif estimate >= (57 << 13): break
        elif estimate >= (56 << 13): break
        elif estimate >= (55 << 13): break
        elif estimate >= (54 << 13): break
        elif estimate >= (53 << 13): break
        elif estimate >= (52 << 13): break
        elif estimate >= (51 << 13): break
        elif estimate >= (50 << 13): break
        elif estimate >= (49 << 13): break
        elif estimate >= (48 << 13): break
        elif estimate >= (47 << 13): break
        elif estimate >= (46 << 13): break
        elif estimate >= (45 << 13): break
        elif estimate >= (44 << 13): break
        elif estimate >= (43 << 13): break
        elif estimate >= (42 << 13): break
        elif estimate >= (41 << 13): break
        elif estimate >= (40 << 13): break
        elif estimate >= (39 << 13): break
        elif estimate >= (38 << 13): break
        elif estimate >= (37 << 13): break
        elif estimate >= (36 << 13): break
        elif estimate >= (35 << 13): break
        elif estimate >= (34 << 13): break
        elif estimate >= (33 << 13): break
        elif estimate >= (32 << 13): break
        elif estimate >= (31 << 13): break
        elif estimate >= (30 << 13): break
        elif estimate >= (29 << 13): break
        elif estimate >= (28 << 13): break
        elif estimate >= (27 << 13): break
        elif estimate >= (26 << 13): break
        elif estimate >= (25 << 13): break
        elif estimate >= (24 << 13): break
        elif estimate >= (23 << 13): break
        elif estimate >= (22 << 13): break
        elif estimate >= (21 << 13): break
        elif estimate >= (20 << 13): break
        elif estimate >= (19 << 13): break
        elif estimate >= (18 << 13): break
        elif estimate >= (17 << 13): break
        elif estimate >= (16 << 13): break
        elif estimate >= (15 << 13): break
        elif estimate >= (14 << 13): break
        elif estimate >= (13 << 13): break
        elif estimate >= (12 << 13): break
        elif estimate >= (11 << 13): break
        elif estimate >= (10 << 13): break
        elif estimate >= (9 << 13): break
        elif estimate >= (8 << 13): break
        elif estimate >= (7 << 13): break
        elif estimate >= (6 << 13): break
        elif estimate >= (5 << 13): break
        elif estimate >= (4 << 13): break
        elif estimate >= (3 << 13): break
        elif estimate >= (2 << 13): break
        elif estimate >= (1 << 13): break

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

    if has_few_characters(string)[0]:
        return
    
    if has_repeating_characters(string)[0]:
        return

    runbench(string)

if __name__ == '__main__':
    atheris.Setup(sys.argv, TestAllWatchedKeywords)
    atheris.Fuzz()