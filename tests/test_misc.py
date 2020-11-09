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


def test_bad_action() -> None:
    with pytest.raises(OSError, match="Invalid argument"):
        pyseccomp.SyscallFilter(0xDEADBEEF)


def test_bad_arch() -> None:
    filt = pyseccomp.SyscallFilter(pyseccomp.ALLOW)

    with pytest.raises(OSError, match="Invalid argument"):
        filt.add_arch(0xDEADBEEF)

    with pytest.raises(OSError, match="Invalid argument"):
        filt.remove_arch(0xDEADBEEF)

    with pytest.raises(OSError, match="Invalid argument"):
        filt.exist_arch(0xDEADBEEF)


def test_bad_rule_args() -> None:
    filt = pyseccomp.SyscallFilter(pyseccomp.ALLOW)

    with pytest.raises(ValueError, match=r"^Too many arguments$"):
        filt.add_rule(
            pyseccomp.KILL_PROCESS,
            "prctl",
            pyseccomp.Arg(1, pyseccomp.EQ, 0),
            pyseccomp.Arg(2, pyseccomp.EQ, 0),
            pyseccomp.Arg(3, pyseccomp.EQ, 0),
            pyseccomp.Arg(4, pyseccomp.EQ, 0),
            pyseccomp.Arg(5, pyseccomp.EQ, 0),
            pyseccomp.Arg(6, pyseccomp.EQ, 0),
            pyseccomp.Arg(7, pyseccomp.EQ, 0),
        )
