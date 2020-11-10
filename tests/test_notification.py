import os
import traceback

import pytest

try:
    from pytest_cov.embed import cleanup as cov_cleanup
    from pytest_cov.embed import init as cov_init
except ImportError:
    cov_init = None
    cov_cleanup = None

import pyseccomp

if not hasattr(pyseccomp._libseccomp, "seccomp_notify_alloc"):  # pylint: disable=protected-access
    pytest.skip("Skipping notification tests", allow_module_level=True)


def test_notification_resp_success() -> None:
    filt = pyseccomp.SyscallFilter(pyseccomp.ALLOW)
    filt.add_rule(pyseccomp.NOTIFY, "setpriority")

    pid = os.fork()
    if pid == 0:
        try:
            if cov_init is not None:
                cov_init()

            filt.load()

            pid = os.fork()
            if pid == 0:
                try:
                    os.setpriority(os.PRIO_PROCESS, 0, os.getpriority(os.PRIO_PROCESS, 0))
                except BaseException:  # pylint: disable=broad-except
                    traceback.print_exc()
                    os._exit(1)  # pylint: disable=protected-access
                finally:
                    os._exit(0)  # pylint: disable=protected-access

            notif = filt.receive_notify()

            assert notif.syscall == pyseccomp.resolve_syscall(pyseccomp.Arch.NATIVE, "setpriority")
            assert notif.syscall_arch == pyseccomp.system_arch()
            assert notif.syscall_args[:3] == [
                os.PRIO_PROCESS,
                0,
                os.getpriority(os.PRIO_PROCESS, 0),
            ]

            filt.respond_notify(pyseccomp.NotificationResponse(0, 0, notif.id, 1))

            _, wstatus = os.waitpid(pid, 0)
            assert os.WIFEXITED(wstatus)
            assert os.WEXITSTATUS(wstatus) == 0

            if cov_cleanup is not None:
                cov_cleanup()

        except BaseException:  # pylint: disable=broad-except
            traceback.print_exc()
            os._exit(1)  # pylint: disable=protected-access
        finally:
            os._exit(0)  # pylint: disable=protected-access

    _, wstatus = os.waitpid(pid, 0)
    assert os.WIFEXITED(wstatus)
    assert os.WEXITSTATUS(wstatus) == 0


def test_notification_bad_length() -> None:
    with pytest.raises(IndexError):
        pyseccomp.Notification(0, 0, 0, 0, 0, 0, [])

    with pytest.raises(IndexError):
        pyseccomp.Notification(0, 0, 0, 0, 0, 0, [0] * 7)
