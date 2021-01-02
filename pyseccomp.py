# pylint: disable=invalid-name,too-few-public-methods
import ctypes
import ctypes.util
import errno
import os
import weakref
from typing import Any, Collection, Iterable, Union, cast, overload

__version__ = "0.1.2"

KILL_PROCESS = 0x80000000
KILL_THREAD = 0x00000000
KILL = KILL_THREAD
TRAP = 0x00030000
NOTIFY = 0x7FC00000
LOG = 0x7FFC0000
ALLOW = 0x7FFF0000


def ERRNO(x: int) -> int:
    return 0x00050000 | (x & 0x0000FFFF)


def TRACE(x: int) -> int:
    return 0x7FF00000 | (x & 0x0000FFFF)


NE = 1
LT = 2
LE = 3
EQ = 4
GE = 5
GT = 6
MASKED_EQ = 7


class _ArgCmp(ctypes.Structure):
    _fields_ = [
        ("arg", ctypes.c_uint),
        ("op", ctypes.c_int),
        ("datum_a", ctypes.c_uint64),
        ("datum_b", ctypes.c_uint64),
    ]


class _SeccompData(ctypes.Structure):
    _fields_ = [
        ("nr", ctypes.c_int),
        ("arch", ctypes.c_uint32),
        ("instruction_pointer", ctypes.c_uint64),
        ("args", (ctypes.c_uint64 * 6)),
    ]


class _Notif(ctypes.Structure):
    _fields_ = [
        ("id", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("data", _SeccompData),
    ]


class _NotifResp(ctypes.Structure):
    _fields_ = [
        ("id", ctypes.c_uint64),
        ("val", ctypes.c_int64),
        ("error", ctypes.c_int32),
        ("flags", ctypes.c_uint32),
    ]


_libc = ctypes.CDLL(ctypes.util.find_library("c"))

_libc.free.argtypes = (ctypes.c_void_p,)
_libc.free.restype = None

_libseccomp_path = ctypes.util.find_library("seccomp")
if _libseccomp_path is None:
    raise RuntimeError("Unable to find libseccomp")

_libseccomp = ctypes.CDLL(_libseccomp_path)

_libseccomp.seccomp_init.argtypes = (ctypes.c_uint32,)
_libseccomp.seccomp_init.restype = ctypes.c_void_p

_libseccomp.seccomp_reset.argtypes = (ctypes.c_void_p, ctypes.c_uint32)
_libseccomp.seccomp_reset.restype = ctypes.c_int

_libseccomp.seccomp_release.argtypes = (ctypes.c_void_p,)
_libseccomp.seccomp_release.restype = None

_libseccomp.seccomp_merge.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
_libseccomp.seccomp_merge.restype = ctypes.c_int

_libseccomp.seccomp_load.argtypes = (ctypes.c_void_p,)
_libseccomp.seccomp_load.restype = ctypes.c_int

_libseccomp.seccomp_attr_set.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.c_uint32)
_libseccomp.seccomp_attr_set.restype = ctypes.c_int

_libseccomp.seccomp_attr_get.argtypes = (
    ctypes.c_void_p,
    ctypes.c_int,
    ctypes.POINTER(ctypes.c_uint32),
)
_libseccomp.seccomp_attr_get.restype = ctypes.c_int

_libseccomp.seccomp_arch_exist.argtypes = (ctypes.c_void_p, ctypes.c_uint32)
_libseccomp.seccomp_arch_exist.restype = ctypes.c_int

_libseccomp.seccomp_arch_add.argtypes = (ctypes.c_void_p, ctypes.c_uint32)
_libseccomp.seccomp_arch_add.restype = ctypes.c_int

_libseccomp.seccomp_arch_remove.argtypes = (ctypes.c_void_p, ctypes.c_uint32)
_libseccomp.seccomp_arch_remove.restype = ctypes.c_int

_libseccomp.seccomp_arch_native.argtypes = ()
_libseccomp.seccomp_arch_native.restype = ctypes.c_uint32

_libseccomp.seccomp_syscall_resolve_num_arch.argtypes = (ctypes.c_uint32, ctypes.c_int)
_libseccomp.seccomp_syscall_resolve_num_arch.restype = ctypes.c_void_p

_libseccomp.seccomp_rule_add_array.argtypes = (
    ctypes.c_void_p,
    ctypes.c_uint32,
    ctypes.c_int,
    ctypes.c_uint,
    ctypes.c_void_p,
)
_libseccomp.seccomp_rule_add_array.restype = ctypes.c_int

_libseccomp.seccomp_rule_add_exact_array.argtypes = (
    ctypes.c_void_p,
    ctypes.c_uint32,
    ctypes.c_int,
    ctypes.c_uint,
    ctypes.c_void_p,
)
_libseccomp.seccomp_rule_add_exact_array.restype = ctypes.c_int

_libseccomp.seccomp_syscall_priority.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.c_uint8)
_libseccomp.seccomp_syscall_priority.restype = ctypes.c_int

try:
    _libseccomp.seccomp_api_get.argtypes = ()
    _libseccomp.seccomp_api_get.restype = ctypes.c_uint

    _libseccomp.seccomp_api_set.argtypes = (ctypes.c_uint,)
    _libseccomp.seccomp_api_set.restype = ctypes.c_int
except AttributeError:
    pass


try:
    _libseccomp.seccomp_notify_alloc.argtypes = (
        ctypes.POINTER(ctypes.POINTER(_Notif)),
        ctypes.POINTER(ctypes.POINTER(_NotifResp)),
    )
    _libseccomp.seccomp_notify_alloc.restype = ctypes.c_int

    _libseccomp.seccomp_notify_free.argtypes = (ctypes.POINTER(_Notif), ctypes.POINTER(_NotifResp))
    _libseccomp.seccomp_notify_free.restype = None

    _libseccomp.seccomp_notify_fd.argtypes = (ctypes.c_void_p,)
    _libseccomp.seccomp_notify_fd.restype = ctypes.c_int

    _libseccomp.seccomp_notify_receive.argtypes = (ctypes.c_int, ctypes.POINTER(_Notif))
    _libseccomp.seccomp_notify_receive.restype = ctypes.c_int

    _libseccomp.seccomp_notify_respond.argtypes = (ctypes.c_int, ctypes.POINTER(_NotifResp))
    _libseccomp.seccomp_notify_respond.restype = ctypes.c_int
except AttributeError:
    pass

_libseccomp.seccomp_export_bpf.argtypes = (ctypes.c_void_p, ctypes.c_int)
_libseccomp.seccomp_export_bpf.restype = ctypes.c_int

_libseccomp.seccomp_export_pfc.argtypes = (ctypes.c_void_p, ctypes.c_int)
_libseccomp.seccomp_export_pfc.restype = ctypes.c_int


def _check_status(res: int) -> None:
    if res < 0:
        raise _build_oserror(-res)


def _build_oserror(
    eno: int,
    filename: Union[str, bytes, None] = None,
    filename2: Union[str, bytes, None] = None,
) -> OSError:
    return OSError(eno, os.strerror(eno), filename, None, filename2)


_EM_386 = 3
_EM_MIPS = 8
_EM_PARISC = 15
_EM_PPC = 20
_EM_PPC64 = 21
_EM_S390 = 22
_EM_ARM = 40
_EM_X86_64 = 62
_EM_AARCH64 = 183
_EM_RISCV = 243

_AUDIT_ARCH_CONVENTION_MIPS64_N32 = 0x20000000
_AUDIT_ARCH_64BIT = 0x80000000
_AUDIT_ARCH_LE = 0x40000000


class Arch:
    NATIVE = 0
    X86 = _EM_386 | _AUDIT_ARCH_LE
    X86_64 = _EM_X86_64 | _AUDIT_ARCH_64BIT | _AUDIT_ARCH_LE
    X32 = _EM_X86_64 | _AUDIT_ARCH_LE
    ARM = _EM_ARM | _AUDIT_ARCH_LE
    AARCH64 = _EM_AARCH64 | _AUDIT_ARCH_64BIT | _AUDIT_ARCH_LE
    MIPS = _EM_MIPS
    MIPS64 = _EM_MIPS | _AUDIT_ARCH_64BIT
    MIPS64N32 = _EM_MIPS | _AUDIT_ARCH_64BIT | _AUDIT_ARCH_CONVENTION_MIPS64_N32
    MIPSEL = _EM_MIPS | _AUDIT_ARCH_LE
    MIPSEL64 = _EM_MIPS | _AUDIT_ARCH_64BIT | _AUDIT_ARCH_LE
    MIPSEL64N32 = _EM_MIPS | _AUDIT_ARCH_64BIT | _AUDIT_ARCH_LE | _AUDIT_ARCH_CONVENTION_MIPS64_N32
    PARISC = _EM_PARISC
    PARISC64 = _EM_PARISC | _AUDIT_ARCH_64BIT
    PPC = _EM_PPC
    PPC64 = _EM_PPC64 | _AUDIT_ARCH_64BIT
    PPC64LE = _EM_PPC64 | _AUDIT_ARCH_64BIT | _AUDIT_ARCH_LE
    S390 = _EM_S390
    S390X = _EM_S390 | _AUDIT_ARCH_64BIT
    RISCV64 = _EM_RISCV | _AUDIT_ARCH_64BIT | _AUDIT_ARCH_LE


class Arg:
    def __init__(self, arg: int, op: int, data_a: int, data_b: int = 0):
        self._arg = arg
        self._op = op
        self._data_a = data_a
        self._data_b = data_b


class Attr:
    ACT_DEFAULT = 1
    ACT_BADARCH = 2
    CTL_NNP = 3
    CTL_TSYNC = 4
    API_TSKIP = 5
    CTL_LOG = 6
    CTL_SSB = 7
    CTL_OPTIMIZE = 8
    API_SYSRAWRC = 9


class Notification:
    def __init__(  # pylint: disable=too-many-arguments
        self,
        id: int,  # pylint: disable=redefined-builtin
        pid: int,
        flags: int,
        syscall: int,
        syscall_arch: int,
        syscall_ip: int,
        syscall_args: Iterable[int],
    ) -> None:
        self.id = id
        self.pid = pid
        self.flags = flags
        self.syscall = syscall
        self.syscall_arch = syscall_arch
        self.syscall_ip = syscall_ip
        self.syscall_args = list(syscall_args)

        if len(self.syscall_args) != 6:
            raise IndexError

    @classmethod
    def _from_raw(cls, raw: _Notif) -> "Notification":
        return cls(
            id=raw.id,
            pid=raw.pid,
            flags=raw.flags,
            syscall=raw.data.nr,
            syscall_arch=raw.data.arch,
            syscall_ip=raw.data.instruction_pointer,
            syscall_args=list(raw.data.args),
        )


class NotificationResponse:
    def __init__(
        self, error: int, flags: int, id: int, val: int  # pylint: disable=redefined-builtin
    ) -> None:
        self.error = error
        self.flags = flags
        self.id = id
        self.val = val

    def _load_into_raw(self, raw: _NotifResp) -> None:
        raw.id = self.id
        raw.val = self.val
        raw.error = self.error
        raw.flags = self.flags


class SyscallFilter:
    def __init__(self, defaction: int) -> None:
        self._defaction = defaction

        self._filter = _libseccomp.seccomp_init(defaction)
        if self._filter is None:
            # Assume EINVAL, even though it could technically be ENOMEM
            raise _build_oserror(errno.EINVAL)

        self._finalizer = weakref.finalize(self, _libseccomp.seccomp_release, self._filter)

    def _refinalize(self) -> None:
        self._finalizer.detach()
        self._finalizer = weakref.finalize(self, _libseccomp.seccomp_release, self._filter)

    def reset(self, defaction: int) -> None:
        _check_status(_libseccomp.seccomp_reset(self._filter, defaction))
        self._refinalize()

    def merge(self, filter: "SyscallFilter") -> None:  # pylint: disable=redefined-builtin
        # pylint: disable=protected-access

        _check_status(_libseccomp.seccomp_merge(self._filter, filter._filter))

        # filter._filter is no longer valid
        filter._filter = _libseccomp.seccomp_init(filter._defaction)
        filter._refinalize()
        if filter._filter is None:
            raise _build_oserror(errno.ENOMEM)

    def load(self) -> None:
        _check_status(_libseccomp.seccomp_load(self._filter))

    def get_attr(self, attr: int) -> int:
        value = ctypes.c_uint32()
        _check_status(_libseccomp.seccomp_attr_get(self._filter, attr, ctypes.byref(value)))
        return value.value

    def set_attr(self, attr: int, value: int) -> None:
        _check_status(_libseccomp.seccomp_attr_set(self._filter, attr, value))

    def add_arch(self, arch: int) -> None:
        _check_status(_libseccomp.seccomp_arch_add(self._filter, arch))

    def remove_arch(self, arch: int) -> None:
        res = _libseccomp.seccomp_arch_remove(self._filter, arch)
        _check_status(res)

    def exist_arch(self, arch: int) -> bool:
        res = _libseccomp.seccomp_arch_exist(self._filter, arch)

        if res == 0:
            return True
        elif res == -errno.EEXIST:
            return False
        else:
            raise _build_oserror(-res)

    def syscall_priority(self, syscall: Union[int, str], priority: int) -> None:
        if isinstance(syscall, str):
            syscall = resolve_syscall(Arch.NATIVE, syscall)

        _check_status(_libseccomp.seccomp_syscall_priority(self._filter, syscall, priority))

    @staticmethod
    def _build_arg_array(args: Collection[Arg]) -> "ctypes.Array[_ArgCmp]":
        # pylint: disable=protected-access

        if len(args) > 6:
            raise ValueError("Too many arguments")

        arr = (_ArgCmp * len(args))()

        for i, arg in enumerate(args):
            arr[i].arg = arg._arg
            arr[i].op = arg._op
            arr[i].datum_a = arg._data_a
            arr[i].datum_b = arg._data_b

        return arr

    def add_rule(self, action: int, syscall: Union[int, str], *args: Arg) -> None:
        if isinstance(syscall, str):
            syscall = resolve_syscall(Arch.NATIVE, syscall)

        arg_arr = self._build_arg_array(args)

        _check_status(
            _libseccomp.seccomp_rule_add_array(self._filter, action, syscall, len(args), arg_arr)
        )

    def add_rule_exactly(self, action: int, syscall: Union[int, str], *args: Arg) -> None:
        if isinstance(syscall, str):
            syscall = resolve_syscall(Arch.NATIVE, syscall)

        arg_arr = self._build_arg_array(args)

        _check_status(
            _libseccomp.seccomp_rule_add_exact_array(
                self._filter, action, syscall, len(args), arg_arr
            )
        )

    def receive_notify(self) -> Notification:
        if not hasattr(_libseccomp, "seccomp_notify_alloc"):
            raise NotImplementedError

        req_ptr = ctypes.POINTER(_Notif)()
        _check_status(_libseccomp.seccomp_notify_alloc(ctypes.byref(req_ptr), None))

        try:
            fd = _libseccomp.seccomp_notify_fd(self._filter)
            _check_status(fd)

            _check_status(_libseccomp.seccomp_notify_receive(fd, req_ptr))
            return Notification._from_raw(req_ptr.contents)  # pylint: disable=protected-access
        finally:
            _libseccomp.seccomp_notify_free(req_ptr, None)

    def respond_notify(self, response: NotificationResponse) -> None:
        if not hasattr(_libseccomp, "seccomp_notify_alloc"):
            raise NotImplementedError

        resp_ptr = ctypes.POINTER(_NotifResp)()
        _check_status(_libseccomp.seccomp_notify_alloc(None, ctypes.byref(resp_ptr)))

        response._load_into_raw(resp_ptr.contents)  # pylint: disable=protected-access

        try:
            fd = _libseccomp.seccomp_notify_fd(self._filter)
            _check_status(fd)

            _check_status(_libseccomp.seccomp_notify_respond(fd, resp_ptr))
        finally:
            _libseccomp.seccomp_notify_free(None, resp_ptr)

    def export_bpf(self, file: Any) -> None:
        _check_status(_libseccomp.seccomp_export_bpf(self._filter, file.fileno()))

    def export_pfc(self, file: Any) -> None:
        _check_status(_libseccomp.seccomp_export_pfc(self._filter, file.fileno()))


def system_arch() -> int:
    return cast(int, _libseccomp.seccomp_arch_native())


def get_api() -> int:
    if not hasattr(_libseccomp, "seccomp_api_get"):
        raise NotImplementedError

    return cast(int, _libseccomp.seccomp_api_get())


def set_api(level: int) -> None:
    if not hasattr(_libseccomp, "seccomp_api_set"):
        raise NotImplementedError

    _check_status(_libseccomp.seccomp_api_set(level))


@overload
def resolve_syscall(arch: int, syscall: int) -> bytes:
    pass  # pragma: no cover


@overload
def resolve_syscall(arch: int, syscall: str) -> int:
    pass  # pragma: no cover


def resolve_syscall(arch: int, syscall: Union[str, int]) -> Union[bytes, int]:
    if isinstance(syscall, int):
        raw_ptr = _libseccomp.seccomp_syscall_resolve_num_arch(arch, syscall)
        if raw_ptr is None:
            raise ValueError("Unknown syscall {} on arch {}".format(syscall, arch))

        res = ctypes.string_at(raw_ptr)
        _libc.free(raw_ptr)
        return res

    else:
        return cast(int, _libseccomp.seccomp_syscall_resolve_name_arch(arch, syscall.encode()))


c_str = str.encode
