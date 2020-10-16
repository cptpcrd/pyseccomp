#!/bin/bash
cd "$(dirname -- "$(dirname -- "$(readlink -f "$0")")")"

for cmd in flake8 isort mypy pylint pytype; do
    if [[ ! -x "$(which "$cmd")" ]]; then
        echo "Could not find $cmd. Please make sure that flake8, isort, mypy, pylint, and pytype are all installed."
        exit 1
    fi
done

flake8 pyseccomp.py tests && isort --check pyseccomp.py tests && mypy --strict -p pyseccomp -p tests && pytype pyseccomp.py tests && pylint pyseccomp.py tests
