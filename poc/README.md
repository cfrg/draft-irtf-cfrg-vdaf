# VDAF reference implementations

This directory contains SageMath implementations of VDAFs. This code is used to
generate test vectors as well as the algorithm definitions in the document
themesleves.

## Installation

This code is compatilbe with SageMath version 9.6.

In order to run the code you will need to install
[PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/index.html).

```
sage --pip install pycryptodomex
```

Version 3.20.0 or later is required.

## Generating test vectors

To generate test vectors, set the value of `TEST_VECTOR` in `common.py` to
`True` and run `make test`.

> TODO Make this an environment variable.

> TODO Pretty-print VDAF name, including associated parameters. (Right now we
> print "<class '__main__.Prio3Aes128Histogram'>", which is rather ugly.)
