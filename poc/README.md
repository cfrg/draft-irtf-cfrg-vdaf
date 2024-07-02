# VDAF reference implementations

This directory contains SageMath implementations of VDAFs. This code is used to
generate test vectors as well as the algorithm definitions in the document
themesleves.

## Installation

This code is compatible with SageMath version 9.6.

In order to run the code you will need to install
[PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/index.html).

```
sage --pip install pycryptodomex
```

Version 3.20.0 or later is required.

## Generating test vectors

To generate test vectors, set environment variable `TEST_VECTOR` to
be `TRUE` when running tests:

```
make TEST_VECTOR=TRUE
```

Users can also specify a custom path to generate the test vectors in
environment variable `TEST_VECTOR_PATH`. For example, to generate
test vectors for Prio3 VDAFs into path `test_vec/00`:

```
TEST_VECTOR=TRUE TEST_VECTOR_PATH=test_vec/00 sage -python -m unittest --quiet tests/test_vdaf_prio3.py
```
