import os
from typing import Union, cast

import pytest

import pyseccomp


def nonsystem_arch() -> int:
    sys_arch = pyseccomp.system_arch()
    return next(arch for arch in [pyseccomp.Arch.X86_64, pyseccomp.Arch.ARM] if arch != sys_arch)


def test_has_arch() -> None:
    filt = pyseccomp.SyscallFilter(defaction=pyseccomp.KILL)

    assert filt.exist_arch(pyseccomp.Arch.NATIVE)
    assert filt.exist_arch(pyseccomp.system_arch())
    assert not filt.exist_arch(nonsystem_arch())


def test_add_arch() -> None:
    filt = pyseccomp.SyscallFilter(defaction=pyseccomp.KILL)

    with pytest.raises(FileExistsError):
        filt.add_arch(pyseccomp.Arch.NATIVE)

    with pytest.raises(FileExistsError):
        filt.add_arch(pyseccomp.system_arch())

    filt.add_arch(nonsystem_arch())


def test_remove_arch_native() -> None:
    filt = pyseccomp.SyscallFilter(defaction=pyseccomp.KILL)

    filt.remove_arch(pyseccomp.Arch.NATIVE)

    with pytest.raises(FileExistsError):
        filt.remove_arch(pyseccomp.system_arch())

    with pytest.raises(FileExistsError):
        filt.remove_arch(nonsystem_arch())


def test_remove_arch_sys() -> None:
    filt = pyseccomp.SyscallFilter(defaction=pyseccomp.KILL)

    filt.remove_arch(pyseccomp.system_arch())

    with pytest.raises(FileExistsError):
        filt.remove_arch(pyseccomp.system_arch())

    with pytest.raises(FileExistsError):
        filt.remove_arch(pyseccomp.Arch.NATIVE)

    with pytest.raises(FileExistsError):
        filt.remove_arch(nonsystem_arch())


def test_reset() -> None:
    filt = pyseccomp.SyscallFilter(pyseccomp.KILL)

    nonsys_arch = nonsystem_arch()
    filt.add_arch(nonsys_arch)
    assert filt.exist_arch(nonsys_arch)

    filt.reset(pyseccomp.KILL)

    # The arch should now be absent
    assert not filt.exist_arch(nonsys_arch)


def test_merge() -> None:
    sys_arch = pyseccomp.system_arch()
    nonsys_arch = nonsystem_arch()

    filt_a = pyseccomp.SyscallFilter(pyseccomp.KILL)

    assert filt_a.exist_arch(sys_arch)
    assert not filt_a.exist_arch(nonsys_arch)

    filt_b = pyseccomp.SyscallFilter(pyseccomp.KILL)
    filt_b.add_arch(nonsys_arch)
    filt_b.remove_arch(sys_arch)

    assert not filt_b.exist_arch(sys_arch)
    assert filt_b.exist_arch(nonsys_arch)

    filt_a.merge(filt_b)

    # Filter A has both
    assert filt_a.exist_arch(sys_arch)
    assert filt_a.exist_arch(nonsys_arch)

    # Filter B was reset
    assert filt_b.exist_arch(sys_arch)
    assert not filt_b.exist_arch(nonsys_arch)


def test_get_set_attr() -> None:
    filt = pyseccomp.SyscallFilter(pyseccomp.KILL)

    filt.set_attr(pyseccomp.Attr.CTL_NNP, 1)
    assert filt.get_attr(pyseccomp.Attr.CTL_NNP) == 1

    filt.set_attr(pyseccomp.Attr.CTL_NNP, 0)
    assert filt.get_attr(pyseccomp.Attr.CTL_NNP) == 0


def test_syscall_priority() -> None:
    filt = pyseccomp.SyscallFilter(pyseccomp.KILL)

    filt.syscall_priority(pyseccomp.resolve_syscall(pyseccomp.Arch.NATIVE, "write"), 100)
    filt.syscall_priority("write", 100)

    for syscall in [pyseccomp.resolve_syscall(pyseccomp.Arch.NATIVE, "NOEXIST"), "NOEXIST"]:
        with pytest.raises(OSError, match=r"Invalid argument"):
            filt.syscall_priority(cast(Union[int, str], syscall), 100)


def test_export_bpf() -> None:
    filt = pyseccomp.SyscallFilter(pyseccomp.KILL)

    r_fd, w_fd = os.pipe()
    with open(r_fd, "rb") as rfile:
        with open(w_fd, "wb") as wfile:
            filt.export_bpf(wfile)

        assert rfile.read() != b""


def test_export_pfc() -> None:
    filt = pyseccomp.SyscallFilter(pyseccomp.KILL)

    r_fd, w_fd = os.pipe()
    with open(r_fd, "rb") as rfile:
        with open(w_fd, "wb") as wfile:
            filt.export_pfc(wfile)

        assert rfile.read() != b""
