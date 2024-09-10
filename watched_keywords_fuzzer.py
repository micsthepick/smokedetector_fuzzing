#!/usr/bin/python
import atheris

## hook on regex ops
#atheris.enabled_hooks.add("RegEx")

with atheris.instrument_imports():
    import regex as re
    import sys

from globalvars import GlobalVars
from blacklists import load_blacklists

from findspam import city_list, regex_compile_no_cache, URL_REGEX, REPEATED_CHARACTER_RATIO


load_blacklists()

KWDS = GlobalVars.watched_keywords.keys()

print(f'loaded {len(KWDS)} KWDS')

def is_simple_regex(pattern):
    # Check for advanced regex features including:
    # - qualifiers: *, +, ?, {n,m}
    # - backreferences: \1, \2, etc.
    # - lookaheads: (?=), (?!)
    # - lookbehinds: (?<=), (?<!)
    advanced_features = [
        r'\*',            # Match *
        r'\+',            # Match +
        r'\?',            # Match ?
        r'\{.*?\}',       # Match {n}, {n,}, {n,m}
        r'\\\d',          # Match backreferences like \1, \2, etc.
        r'\(\?[:=!]',     # Match lookaheads: (?=), (?!)
        r'\(\?<=',        # Match positive lookbehind: (?<=)
        r'\(\?<!',        # Match negative lookbehind: (?<!)
    ]
    
    # Combine all advanced features into one big regex
    advanced_regex = '|'.join(advanced_features)
    
    # If any advanced feature is found, it's not a simple regex
    if re.search(advanced_regex, pattern):
        return False
    
    return True

REGEXES = [regex_compile_no_cache(kw, re.UNICODE, city=city_list, ignore_unused=True) for kw in KWDS if not is_simple_regex(kw)]

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
    # Check each REGEX one by one, recording how long data takes
    # find out which took the longest, and print it

    if len(data) < 2:
        return

    fdp = atheris.FuzzedDataProvider(data)

    string = fdp.ConsumeUnicode(len(data) - 2)

    if len({'\0', '\r', '\n'} & set(string)) > 0:
        return

    if has_few_characters(string)[0]:
        return
    
    if has_repeating_characters(string)[0]:
        return

    index = fdp.ConsumeIntInRange(0, len(REGEXES)-1)

    ##fuzz_me(index, string)
    min_match_num_1 = None
    min_match_num_2 = None
    min_match_num_3 = None
    max_fail_num_1 = None
    max_fail_num_2 = None
    max_fail_num_3 = None
    is_match = False
    for i in range(len(REGEXES)):
        stack_sizes = REGEXES[i].scanner(string).bench()
        if stack_sizes[0]:
            is_match = True
            min_match_num_1 = stack_sizes[1] if (min_match_num_1 is None) else (stack_sizes[1] if (stack_sizes[1] < min_match_num_1) else min_match_num_1)
            min_match_num_2 = stack_sizes[2] if (min_match_num_2 is None) else (stack_sizes[2] if (stack_sizes[2] < min_match_num_2) else min_match_num_2)
            min_match_num_3 = stack_sizes[3] if (min_match_num_3 is None) else (stack_sizes[3] if (stack_sizes[3] < min_match_num_3) else min_match_num_3)
        else:
            max_fail_num_1 = stack_sizes[1] if (max_fail_num_1 is None) else (stack_sizes[1] if (stack_sizes[1] > max_fail_num_1) else max_fail_num_1)
            max_fail_num_2 = stack_sizes[2] if (max_fail_num_2 is None) else (stack_sizes[2] if (stack_sizes[2] > max_fail_num_2) else max_fail_num_2)
            max_fail_num_3 = stack_sizes[3] if (max_fail_num_3 is None) else (stack_sizes[3] if (stack_sizes[3] > max_fail_num_3) else max_fail_num_3)
    min_match_num_1 = min_match_num_1 if min_match_num_1 is not None else 0
    min_match_num_2 = min_match_num_2 if min_match_num_2 is not None else 0
    min_match_num_3 = min_match_num_3 if min_match_num_3 is not None else 0
    max_fail_num_1 = max_fail_num_1 if max_fail_num_1 is not None else 0
    max_fail_num_2 = max_fail_num_2 if max_fail_num_2 is not None else 0
    max_fail_num_3 = max_fail_num_3 if max_fail_num_3 is not None else 0
    estimate = max(min_match_num_1, min_match_num_2, min_match_num_3) if is_match else max(max_fail_num_1, max_fail_num_2, max_fail_num_3)
    if estimate >= (1 << 17):
        raise ValueError(repr(f'BOOM! [[[{string!r}]]] !BOOM'))
    elif estimate >= (15 << 13):
        print("15<<13", repr(string))
    elif estimate >= (14 << 13):
        print("14<<13", repr(string))
    elif estimate >= (13 << 13):
        print("13<<13", repr(string))
    elif estimate >= (12 << 13):
        print("12<<13", repr(string))
    elif estimate >= (11 << 13):
        print("11<<13", repr(string))
    elif estimate >= (10 << 13):
        print("10<<13", repr(string))
    elif estimate >= (9 << 13):
        print("9<<13", repr(string))
    elif estimate >= (8 << 13):
        print("8<<13", repr(string))
    elif estimate >= (7 << 13):
        print("7<<13", repr(string))
    elif estimate >= (6 << 13):
        print("6<<13", repr(string))
    elif estimate >= (5 << 13):
        print("5<<13", repr(string))
    elif estimate >= (4 << 13):
        print("4<<13", repr(string))
    elif estimate >= (3 << 13):
        print("3<<13", repr(string))
    elif estimate >= (2 << 13):
        print("2<<13", repr(string))
    elif estimate >= (1 << 13):
        pass
    elif estimate >= (1 << 12):
        pass
    elif estimate >= (1 << 11):
        pass
    elif estimate >= (1 << 10):
        pass
    elif estimate >= (1 << 9):
        pass
    elif estimate >= (1 << 8):
        pass
    elif estimate >= (1 << 7):
        pass
atheris.Setup(sys.argv, TestAllWatchedKeywords)
atheris.Fuzz()
