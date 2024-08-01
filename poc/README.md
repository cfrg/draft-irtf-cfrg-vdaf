# VDAF reference implementations

This directory contains a reference implementation of the VDAFs specified in
[draft-irtf-cfrg-vdaf](https://datatracker.ietf.org/doc/draft-irtf-cfrg-vdaf/).
It is not intended for production use: the code is not optimized for
performance or resistance to side-channel attacks. Its primary purpose is to
generate test vectors.

## Installation

This code requires [SageMath](https://www.sagemath.org/) version >= 9.6 to run. To install:

```
sage -pip install git+https://github.com/cfrg/draft-irtf-cfrg-vdaf@draft-irtf-cfrg-vdaf-11#subdirectory=poc
```

where draft-irtf-cfrg-vdaf-11 is the desired tag. The installed package is called `vdaf_poc`:

```
sage -c "from vdaf_poc.field import Field64; print((Field64.MODULUS - 1).factor())"
```

## Development

To run unit tests, you'll first need to install
[PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/index.html) >=
3.20.0:

```
sage -pip install pycryptodomex
```

Now you should be able to run the unit tests:

```
sage -python -m unittest
```

## Generating test vectors

To generate test vectors, run:

```
sage -python gen_test_vec.py
```

Users can also specify a custom path to generate the test vectors in
environment variable `TEST_VECTOR_PATH`:

```
TEST_VECTOR_PATH=path/to/test_vec sage -python gen_test_vec.py
```
