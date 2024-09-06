#!/usr/bin/python
import atheris

with atheris.instrument_imports():
    from globalvars import GlobalVars
    from blacklists import load_blacklists
    from helpers import keyword_bookend_regex_text
    import time
    import regex
    import sys

load_blacklists()

KWDS = GlobalVars.bad_keywords

REGEXES = [regex.compile(keyword_bookend_regex_text(kw)) for kw in KWDS]

@atheris.instrument_func
def TestAllWatchedKeywords(data: bytes):
    # Check each REGEX one by one, recording how long data takes
    # find out which took the longest, and print it

    # first make sure that we are using valid unicode.
    try:
        string = str(data, encoding='utf-8')
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
    
    if longest_time > 0.25:
        # Print the slowest regex and the time it took if it takes a considerable time
        print(f"\nSlowest regex: {slowest_regex.pattern}, Time taken: {longest_time:.4f} seconds")
        raise RuntimeError('Boom')


atheris.Setup(sys.argv, TestAllWatchedKeywords)
atheris.Fuzz()
