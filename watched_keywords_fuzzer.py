#!/usr/bin/python
import atheris

from globalvars import GlobalVars
from blacklists import load_blacklists

from findspam import city_list, regex_compile_no_cache

with atheris.instrument_imports():
    import time
    import regex
    import sys

load_blacklists()

KWDS = GlobalVars.watched_keywords.keys()

print(f'loaded {len(KWDS)} KWDS')

REGEXES = [regex_compile_no_cache(kw, regex.UNICODE, city=city_list, ignore_unused=True) for kw in KWDS if len(set('<>[]()') & set(kw))]


print(f'rejected {len(KWDS)-len(REGEXES)} KWDS (too simple) and left with {len(REGEXES)}')

@atheris.instrument_func
def TestAllWatchedKeywords(data: bytes):
    # Check each REGEX one by one, recording how long data takes
    # find out which took the longest, and print it

    fdp = atheris.FuzzedDataProvider(data)

    try:
        string = fdp.ConsumeUnicode(len(data))
    except UnicodeDecodeError:
        return

    longest_time = 0
    slowest_regex = None

    for r in REGEXES:
        start_time = time.time()  # Start the timer

        # Apply the regex search or match (adjust based on your use case)
        r.search(string)

        end_time = time.time()  # End the timer
        elapsed_time = end_time - start_time

        # Check if this regex took the longest
        if elapsed_time > longest_time:
            longest_time = elapsed_time
            slowest_regex = r
        if elapsed_time > 0.0001:
            pass
        elif elapsed_time > 0.0003:
            pass
        elif elapsed_time > 0.001:
            pass
        elif elapsed_time > 0.003:
            pass
        elif elapsed_time > 0.01:
            pass
        elif elapsed_time > 0.03:
            pass
        elif elapsed_time > 0.1:
            pass
        elif elapsed_time > 0.3:
            pass

    if longest_time > 1:
        # Print the slowest regex and the time it took if it takes a considerable time
        print(f"\nSlowest regex: {slowest_regex.pattern}, Time taken: {longest_time:.4f} seconds")
        raise RuntimeError('Boom')


atheris.Setup(sys.argv, TestAllWatchedKeywords)
atheris.Fuzz()
