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

    for i in range(len(string)):
        if len(data_unicode) <= i or data_unicode[i] != string[i]:
            break
    else:
        raise ValueError("BOOM!")


if __name__ == '__main__':
    atheris.Setup(sys.argv, Fuzz)
    atheris.Fuzz()