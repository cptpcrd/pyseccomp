import pytest

import pyseccomp


def test_resolve_syscall() -> None:
    write_nr = pyseccomp.resolve_syscall(pyseccomp.Arch.NATIVE, "write")

    assert pyseccomp.resolve_syscall(pyseccomp.Arch.NATIVE, write_nr) == b"write"

    with pytest.raises(ValueError, match="Unknown syscall"):
        pyseccomp.resolve_syscall(pyseccomp.Arch.NATIVE, -1)

    with pytest.raises(ValueError, match="Unknown syscall"):
        pyseccomp.resolve_syscall(pyseccomp.Arch.NATIVE, -2)

    assert pyseccomp.resolve_syscall(pyseccomp.Arch.NATIVE, "NO_SYSCALL") == -1


def test_api_get_set() -> None:
    orig_api = pyseccomp.get_api()

    try:
        pyseccomp.set_api(1)
        assert pyseccomp.get_api() == 1

        pyseccomp.set_api(2)
        assert pyseccomp.get_api() == 2
    finally:
        pyseccomp.set_api(orig_api)
