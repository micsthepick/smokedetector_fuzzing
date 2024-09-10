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


maxes = [0,0,0]

@atheris.instrument_func
def fuzz_me(index, string):
    match = REGEXES[index].search(string)

    if match is not None:
        if max(match.stack_sizes) > 1000:
            pass
        if max(match.stack_sizes) > 10000:
            pass
        if max(match.stack_sizes) > 100000:
            raise RuntimeError(repr(f'BOOM: [[[{match.string}]]]'))
        if match.stack_sizes[0] > maxes[0]:
            maxes[0] = match.stack_sizes[0]
            print(f'NEW GROUND! {match.stack_sizes[0]}@0')
        if match.stack_sizes[1] > maxes[1]:
            maxes[1] = match.stack_sizes[1]
            print(f'NEW GROUND! {match.stack_sizes[1]}@1')
        if match.stack_sizes[2] > maxes[2]:
            maxes[2] = match.stack_sizes[2]
            print(f'NEW GROUND! {match.stack_sizes[2]}@2')

@atheris.instrument_func
def TestAllWatchedKeywords(data: bytes):
    global maxes
    # Check each REGEX one by one, recording how long data takes
    # find out which took the longest, and print it

    if len(data) < 2:
        return

    fdp = atheris.FuzzedDataProvider(data)

    string = fdp.ConsumeUnicode(len(data) - 2)

    if '\0' in string:
        return

    index = fdp.ConsumeIntInRange(0, len(REGEXES)-1)

    ##fuzz_me(index, string)
    for i in range(len(REGEXES)):
        fuzz_me(i, string)

atheris.Setup(sys.argv, TestAllWatchedKeywords)
atheris.Fuzz()
