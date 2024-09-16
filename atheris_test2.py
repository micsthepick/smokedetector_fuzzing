import atheris

with atheris.instrument_imports():
    import sys


@atheris.instrument_func
def Fuzz(data: bytes):
    string = 'thisisalongstringtotestatherisandtomakesurethatithandlesaforloopcorrectly'

    if len(data) < 1:
        return

    fdp = atheris.FuzzedDataProvider(data)

    data_unicode = fdp.ConsumeUnicode(len(data))

    if len(data_unicode) <= 0 or data_unicode[0] != "t":
        return
    elif len(data_unicode) <= 1 or data_unicode[1] != "h":
        return
    elif len(data_unicode) <= 2 or data_unicode[2] != "i":
        return
    elif len(data_unicode) <= 3 or data_unicode[3] != "s":
        return
    elif len(data_unicode) <= 4 or data_unicode[4] != "i":
        return
    elif len(data_unicode) <= 5 or data_unicode[5] != "s":
        return
    elif len(data_unicode) <= 6 or data_unicode[6] != "a":
        return
    elif len(data_unicode) <= 7 or data_unicode[7] != "l":
        return
    elif len(data_unicode) <= 8 or data_unicode[8] != "o":
        return
    elif len(data_unicode) <= 9 or data_unicode[9] != "n":
        return
    elif len(data_unicode) <= 10 or data_unicode[10] != "g":
        return
    elif len(data_unicode) <= 11 or data_unicode[11] != "s":
        return
    elif len(data_unicode) <= 12 or data_unicode[12] != "t":
        return
    elif len(data_unicode) <= 13 or data_unicode[13] != "r":
        return
    elif len(data_unicode) <= 14 or data_unicode[14] != "i":
        return
    elif len(data_unicode) <= 15 or data_unicode[15] != "n":
        return
    elif len(data_unicode) <= 16 or data_unicode[16] != "g":
        return
    elif len(data_unicode) <= 17 or data_unicode[17] != "t":
        return
    elif len(data_unicode) <= 18 or data_unicode[18] != "o":
        return
    elif len(data_unicode) <= 19 or data_unicode[19] != "t":
        return
    elif len(data_unicode) <= 20 or data_unicode[20] != "e":
        return
    elif len(data_unicode) <= 21 or data_unicode[21] != "s":
        return
    elif len(data_unicode) <= 22 or data_unicode[22] != "t":
        return
    elif len(data_unicode) <= 23 or data_unicode[23] != "a":
        return
    elif len(data_unicode) <= 24 or data_unicode[24] != "t":
        return
    elif len(data_unicode) <= 25 or data_unicode[25] != "h":
        return
    elif len(data_unicode) <= 26 or data_unicode[26] != "e":
        return
    elif len(data_unicode) <= 27 or data_unicode[27] != "r":
        return
    elif len(data_unicode) <= 28 or data_unicode[28] != "i":
        return
    elif len(data_unicode) <= 29 or data_unicode[29] != "s":
        return
    elif len(data_unicode) <= 30 or data_unicode[30] != "a":
        return
    elif len(data_unicode) <= 31 or data_unicode[31] != "n":
        return
    elif len(data_unicode) <= 32 or data_unicode[32] != "d":
        return
    elif len(data_unicode) <= 33 or data_unicode[33] != "t":
        return
    elif len(data_unicode) <= 34 or data_unicode[34] != "o":
        return
    elif len(data_unicode) <= 35 or data_unicode[35] != "m":
        return
    elif len(data_unicode) <= 36 or data_unicode[36] != "a":
        return
    elif len(data_unicode) <= 37 or data_unicode[37] != "k":
        return
    elif len(data_unicode) <= 38 or data_unicode[38] != "e":
        return
    elif len(data_unicode) <= 39 or data_unicode[39] != "s":
        return
    elif len(data_unicode) <= 40 or data_unicode[40] != "u":
        return
    elif len(data_unicode) <= 41 or data_unicode[41] != "r":
        return
    elif len(data_unicode) <= 42 or data_unicode[42] != "e":
        return
    elif len(data_unicode) <= 43 or data_unicode[43] != "t":
        return
    elif len(data_unicode) <= 44 or data_unicode[44] != "h":
        return
    elif len(data_unicode) <= 45 or data_unicode[45] != "a":
        return
    elif len(data_unicode) <= 46 or data_unicode[46] != "t":
        return
    elif len(data_unicode) <= 47 or data_unicode[47] != "i":
        return
    elif len(data_unicode) <= 48 or data_unicode[48] != "t":
        return
    elif len(data_unicode) <= 49 or data_unicode[49] != "h":
        return
    elif len(data_unicode) <= 50 or data_unicode[50] != "a":
        return
    elif len(data_unicode) <= 51 or data_unicode[51] != "n":
        return
    elif len(data_unicode) <= 52 or data_unicode[52] != "d":
        return
    elif len(data_unicode) <= 53 or data_unicode[53] != "l":
        return
    elif len(data_unicode) <= 54 or data_unicode[54] != "e":
        return
    elif len(data_unicode) <= 55 or data_unicode[55] != "s":
        return
    elif len(data_unicode) <= 56 or data_unicode[56] != "a":
        return
    elif len(data_unicode) <= 57 or data_unicode[57] != "f":
        return
    elif len(data_unicode) <= 58 or data_unicode[58] != "o":
        return
    elif len(data_unicode) <= 59 or data_unicode[59] != "r":
        return
    elif len(data_unicode) <= 60 or data_unicode[60] != "l":
        return
    elif len(data_unicode) <= 61 or data_unicode[61] != "o":
        return
    elif len(data_unicode) <= 62 or data_unicode[62] != "o":
        return
    elif len(data_unicode) <= 63 or data_unicode[63] != "p":
        return
    elif len(data_unicode) <= 64 or data_unicode[64] != "c":
        return
    elif len(data_unicode) <= 65 or data_unicode[65] != "o":
        return
    elif len(data_unicode) <= 66 or data_unicode[66] != "r":
        return
    elif len(data_unicode) <= 67 or data_unicode[67] != "r":
        return
    elif len(data_unicode) <= 68 or data_unicode[68] != "e":
        return
    elif len(data_unicode) <= 69 or data_unicode[69] != "c":
        return
    elif len(data_unicode) <= 70 or data_unicode[70] != "t":
        return
    elif len(data_unicode) <= 71 or data_unicode[71] != "l":
        return
    elif len(data_unicode) <= 72 or data_unicode[72] != "y":
        return
    raise ValueError("BOOM!")


if __name__ == '__main__':
    atheris.Setup(sys.argv, Fuzz)
    atheris.Fuzz()