import sys

sys.path.append(".")
from ctypes import *

import ftea

PyCapsule_GetPointer = pythonapi.PyCapsule_GetPointer

PyCapsule_GetPointer.argtypes = [py_object, c_char_p]
PyCapsule_GetPointer.restype = c_void_p

p = cast(
    PyCapsule_GetPointer(ftea.ftea_encrypt_len, b"ftea.ftea_encrypt_len"), c_void_p
)
func = cast(p, CFUNCTYPE(c_longlong, c_longlong))
print(func(20))
