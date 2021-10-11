# BCD: Cross-architecture Binary Comparison DB

workflow:
`binary -> retdec lift into llvm-ir -> minhash -> db` 

Stores functions in binaries as minhash sets for quick lookup for similar functions.
Example usecases:
- detect libc functions with stripped names (demangling)
- detect similar functions in other binaries (e.g. malware analysis/clustering)
- match functions in a binary with open source functions (source code recovery / decompiling)

## pre-requisites

(can comment out ssdeep and pysimhash if not running experiments, the main db is in minhash)

`pip3 install -r requirements.txt`

need to install retdec from https://github.com/avast/retdec
and place `retdec-decompiler` on PATH

### index functions in a binary 

`./bcd.py -i /bin/whoami`

(if no picklefile specified, a new db is saved in the `db_dict.pkl`)

### search similar functions from a binary

`./bcd.py /bin/echo`

## usage recommendations

- index binaries that have symbols (not stripped) for symbol demangling
	- to see binaries with symbols, use `nm <path to binary>` on linux/mac (use WSL if you are on windows)

- index known functions, like crypto routines, to detect similar crypto routines (e.g. in ransomware)
