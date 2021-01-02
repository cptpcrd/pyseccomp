import ctypes
from typing import Tuple

import pyseccomp


class _SeccompVersion(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("major", ctypes.c_uint),
        ("minor", ctypes.c_uint),
        ("micro", ctypes.c_uint),
    ]


pyseccomp._libseccomp.seccomp_version.restype = ctypes.POINTER(  # pylint: disable=protected-access
    _SeccompVersion
)


def seccomp_version() -> Tuple[int, int, int]:
    ver = pyseccomp._libseccomp.seccomp_version().contents  # pylint: disable=protected-access
    return ver.major, ver.minor, ver.micro
