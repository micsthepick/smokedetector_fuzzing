import atheris
import regex


with atheris.instrument_imports():
    import sys

def TestOneInput(data):
    pass  # No regex or other libraries

atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
