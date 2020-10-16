# pylint: disable=protected-access
import errno
import os

import pytest

import pyseccomp


def test_check_status() -> None:
    pyseccomp._check_status(0)
    pyseccomp._check_status(1)

    with pytest.raises(PermissionError):
        pyseccomp._check_status(-errno.EPERM)


def test_build_oserror() -> None:
    for eno in [errno.EINVAL, errno.EPERM]:
        assert os.strerror(eno) in str(pyseccomp._build_oserror(eno))
