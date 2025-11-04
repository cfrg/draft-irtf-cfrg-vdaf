# VDAF reference implementations

This directory contains a reference implementation of the VDAFs specified in
[draft-irtf-cfrg-vdaf](https://datatracker.ietf.org/doc/draft-irtf-cfrg-vdaf/).
It is not intended for production use: the code is not optimized for
performance or resistance to side-channel attacks. Its primary purpose is to
generate test vectors.

## Installation

This code requires Python 3.12 or later to run. To install:

```
python -m pip install git+https://github.com/cfrg/draft-irtf-cfrg-vdaf@draft-irtf-cfrg-vdaf-11#subdirectory=poc
```

where draft-irtf-cfrg-vdaf-11 is the desired tag. The installed package is called `vdaf_poc`:

```
python -c "from vdaf_poc.field import Field64; print(Field64.MODULUS)"
```

## Development

Install poetry following these [instructions](https://python-poetry.org/docs/#installation):

```sh
export POETRY_HOME=/opt/poetry
python -m venv $POETRY_HOME
$POETRY_HOME/bin/pip install poetry==2.2.0
```

Use poetry to install project's dependencies.

```sh
poetry install
```

## Testing

Now, we can run the unit tests:

```sh
poetry run poe tests
```

## Generating test vectors

To generate test vectors, run:

```sh
poetry run poe vectors
```

Users can also specify a custom path to generate the test vectors in
the environment variable `TEST_VECTOR_PATH`:

```sh
TEST_VECTOR_PATH=path/to/test_vec poetry run poe vectors
```

## Generating Documentation

Generate HTML documentation by running.

```sh
poetry run poe docs
```

The documentation is at the `./html/index.html` file.

## Formatting Code

Before submitting code, make sure the code is properly formatted.

```sh
poetry run poe check
```

Otherwise, let the tools format the code.

```sh
poetry run poe format
```

## Linter

Run some checks to verify code quality and type annotations.

```sh
poetry run poe lint
```
