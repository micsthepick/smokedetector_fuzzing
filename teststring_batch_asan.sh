ASAN_OPTIONS=detect_leaks=0:quarantine_size=1024 LD_PRELOAD=$(python -c "import atheris; print(atheris.path())")/asan_with_fuzzer.so python batch_pool_testspam.py "$@"
