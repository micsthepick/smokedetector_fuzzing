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

from findspam import city_list, regex_compile_no_cache


load_blacklists()

KWDS = GlobalVars.watched_keywords.keys()

print(f'loaded {len(KWDS)} KWDS')

REGEXES = [regex_compile_no_cache(kw, re.UNICODE, city=city_list, ignore_unused=True) for kw in KWDS if len(set(kw) - set('qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM./\\'))]

print(f'rejected {len(KWDS)-len(REGEXES)} KWDS (too simple) and left with {len(REGEXES)}')

@atheris.instrument_func
def fuzz_me(index, string):
    match = REGEXES[index].search(string)

    if match is not None:
        max_num = max(match.stack_sizes)
        if max_num >= (1 << 10):
            for i in range(16, 9):
               if ((1<<i)&max_num):
                    print(i)
                    break
        if max_num > (1 << 17):
            raise ValueError(repr(f'BOOM! [[[{match.string}]]] !BOOM'))

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

    index = fdp.ConsumeIntInRange(0, len(REGEXES)-1)

    ##fuzz_me(index, string)
    for i in range(len(REGEXES)):
        fuzz_me(i, string)

atheris.Setup(sys.argv, TestAllWatchedKeywords)
atheris.Fuzz()
