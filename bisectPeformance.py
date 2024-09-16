#!/usr/bin/python
import atheris
import sys
import regex
from tqdm import tqdm
from findspam import GlobalVars, get_bookended_keyword_regex_text_from_entries, city_list

MAXPOSTLEN = 28000
# 30 000 according to meta/q/176445

def runregex(string, regexes):
    regex_raw = get_bookended_keyword_regex_text_from_entries(regexes)
    regex_raw = '^(?:' + '|'.join(regexes) + ')$'
    compiled = regex.compile(regex_raw, regex.UNICODE, city=city_list, ignore_unused=True)
    return compiled.scanner(string).bench()[-1]

def getslowest(string, regexes):
    slowest_num = 0
    for regex in tqdm(regexes):
        t = runregex(string, [regex])
        if t > slowest_num:
            slowest_num = t
            slowest_regex = regex
    print("slowest regex:", slowest_num, slowest_regex)
    # if len(regexes) > 1:
    #     regexes_L = regexes[:len(regexes)//2]
    #     regexes_R = regexes[(len(regexes)+1)//2:]
    #     a = runregex(string, regexes_L)
    #     b = runregex(string, regexes_R)
    #     print(a, b, len(regexes_L), len(regexes_R))
    #     if len(regexes_L) < 6:
    #         print (regexes, regexes_L, regexes_R)
    #     if a < b:
    #         return getslowest(string, regexes_R)
    #     else:
    #         return getslowest(string, regexes_L)
    # else:
    #     return regexes[0]

def TestAllWatchedKeywords(data: bytes):
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

    lhs, mid, rhs = string[:split1], string[split1:split2], string[split2:]
    maxpump = (MAXPOSTLEN - (len(lhs) + len(rhs))) // len(mid)
    string = lhs+mid*maxpump+rhs

    regexes = list(GlobalVars.watched_keywords.keys())

    getslowest(string, regexes)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage: python script.py <testCase>')
    with open(sys.argv[1], 'rb') as f:
        data = f.read()
    TestAllWatchedKeywords(data)