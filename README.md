# pyseccomp

[![PyPI](https://img.shields.io/pypi/v/pyseccomp)](https://pypi.org/project/pyseccomp)
[![Python Versions](https://img.shields.io/pypi/pyversions/pyseccomp)](https://pypi.org/project/pyseccomp)
[![GitHub Actions](https://github.com/cptpcrd/pyseccomp/workflows/CI/badge.svg?branch=master&event=push)](https://github.com/cptpcrd/pyseccomp/actions?query=workflow%3ACI+branch%3Amaster+event%3Apush)
[![codecov](https://codecov.io/gh/cptpcrd/pyseccomp/branch/master/graph/badge.svg)](https://codecov.io/gh/cptpcrd/pyseccomp)

An interface to libseccomp using ctypes.

This library is API compatible with libseccomp's Python bindings, but it's available on PyPI and it's written in pure Python.

This is the intended use case:

```python
try:
    import seccomp
except ImportError:
    import pyseccomp as seccomp
```
