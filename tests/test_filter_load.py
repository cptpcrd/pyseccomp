import errno
import os
import signal
import traceback

import pytest

try:
    from pytest_cov.embed import cleanup as cov_cleanup
    from pytest_cov.embed import init as cov_init
except ImportError:
    cov_init = None
    cov_cleanup = None

import pyseccomp


def test_nice_eperm() -> None:
    filt = pyseccomp.SyscallFilter(pyseccomp.ALLOW)

    filt.add_rule(pyseccomp.ERRNO(errno.EPERM), "nice")
    filt.add_rule(pyseccomp.ERRNO(errno.EPERM), "setpriority")

    pid = os.fork()
    if pid == 0:
        try:
            if cov_init is not None:
                cov_init()

            os.nice(0)

            filt.load()

            with pytest.raises(PermissionError):
                os.nice(0)

            if cov_cleanup is not None:
                cov_cleanup()

        except Exception:  # pylint: disable=broad-except
            traceback.print_exc()
            os._exit(1)  # pylint: disable=protected-access
        finally:
            os._exit(0)  # pylint: disable=protected-access

    _, wstatus = os.waitpid(pid, 0)
    assert os.WIFEXITED(wstatus)
    assert os.WEXITSTATUS(wstatus) == 0


def test_nice_eperm_exactly() -> None:
    filt = pyseccomp.SyscallFilter(pyseccomp.ALLOW)

    for name in ["nice", "setpriority"]:
        sys_nr = pyseccomp.resolve_syscall(pyseccomp.Arch.NATIVE, name)
        if sys_nr >= 0:
            filt.add_rule_exactly(pyseccomp.ERRNO(errno.EPERM), sys_nr)

    pid = os.fork()
    if pid == 0:
        try:
            os.nice(0)

            filt.load()

            with pytest.raises(PermissionError):
                os.nice(0)

        except Exception:  # pylint: disable=broad-except
            traceback.print_exc()
            os._exit(1)  # pylint: disable=protected-access
        finally:
            os._exit(0)  # pylint: disable=protected-access

    _, wstatus = os.waitpid(pid, 0)
    assert os.WIFEXITED(wstatus)
    assert os.WEXITSTATUS(wstatus) == 0


def test_getpriority_pid_1() -> None:
    filt = pyseccomp.SyscallFilter(pyseccomp.ALLOW)

    filt.add_rule(pyseccomp.ERRNO(errno.EPERM), "getpriority", pyseccomp.Arg(1, pyseccomp.EQ, 1))

    pid = os.fork()
    if pid == 0:
        try:
            os.getpriority(os.PRIO_PROCESS, 0)
            os.getpriority(os.PRIO_PROCESS, 1)

            filt.load()

            os.getpriority(os.PRIO_PROCESS, 0)

            with pytest.raises(PermissionError):
                os.getpriority(os.PRIO_PROCESS, 1)

        except Exception:  # pylint: disable=broad-except
            traceback.print_exc()
            os._exit(1)  # pylint: disable=protected-access
        finally:
            os._exit(0)  # pylint: disable=protected-access

    _, wstatus = os.waitpid(pid, 0)
    assert os.WIFEXITED(wstatus)
    assert os.WEXITSTATUS(wstatus) == 0


def test_nice_kill() -> None:
    filt = pyseccomp.SyscallFilter(pyseccomp.ALLOW)

    filt.add_rule(pyseccomp.KILL, pyseccomp.resolve_syscall(pyseccomp.Arch.NATIVE, "nice"))
    filt.add_rule(pyseccomp.KILL, pyseccomp.resolve_syscall(pyseccomp.Arch.NATIVE, "setpriority"))

    pid = os.fork()
    if pid == 0:
        try:
            os.nice(0)

            filt.load()

            os.nice(0)
        finally:
            os._exit(0)  # pylint: disable=protected-access

    _, wstatus = os.waitpid(pid, 0)
    assert os.WIFSIGNALED(wstatus)
    assert os.WTERMSIG(wstatus) == signal.SIGSYS


def test_nice_kill_exactly() -> None:
    filt = pyseccomp.SyscallFilter(pyseccomp.ALLOW)

    for name in ["nice", "setpriority"]:
        sys_nr = pyseccomp.resolve_syscall(pyseccomp.Arch.NATIVE, name)
        if sys_nr >= 0:
            filt.add_rule_exactly(pyseccomp.KILL, name)

    pid = os.fork()
    if pid == 0:
        try:
            os.nice(0)

            filt.load()

            os.nice(0)
        finally:
            os._exit(0)  # pylint: disable=protected-access

    _, wstatus = os.waitpid(pid, 0)
    assert os.WIFSIGNALED(wstatus)
    assert os.WTERMSIG(wstatus) == signal.SIGSYS
