
import ctypes
import ctypes.wintypes

from ctypes.wintypes import BOOL
from ctypes.wintypes import DWORD
from ctypes.wintypes import HANDLE
from ctypes.wintypes import LPVOID
from ctypes.wintypes import LPCVOID

import functools

import struct

LPCSTR = LPCTSTR = ctypes.c_char_p
LPDWORD = PDWORD = ctypes.POINTER(DWORD)

class _SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [('nLength', DWORD),
                ('lpSecurityDescriptor', LPVOID),
                ('bInheritHandle', BOOL),]
SECURITY_ATTRIBUTES = _SECURITY_ATTRIBUTES
LPSECURITY_ATTRIBUTES = ctypes.POINTER(_SECURITY_ATTRIBUTES)
LPTHREAD_START_ROUTINE = LPVOID

DELETE = 0x00010000L #    Required to delete the object.
READ_CONTROL = 0x00020000L #  Required to read information in the security descriptor for the object, not including the information in the SACL. To read or write the SACL, you must request the ACCESS_SYSTEM_SECURITY access right. For more information, see SACL Access Right.
SYNCHRONIZE = 0x00100000L #   The right to use the object for synchronization. This enables a thread to wait until the object is in the signaled state.
WRITE_DAC = 0x00040000L # Required to modify the DACL in the security descriptor for the object.
WRITE_OWNER = 0x00080000L #   Required to change the owner in the security descriptor for the object.
PROCESS_CREATE_PROCESS = 0x0080 # Required to create a process.
PROCESS_CREATE_THREAD = 0x0002 #  Required to create a thread.
PROCESS_DUP_HANDLE = 0x0040 # Required to duplicate a handle using DuplicateHandle.
PROCESS_QUERY_INFORMATION = 0x0400 #  Required to retrieve certain information about a process, such as its token, exit code, and priority class = see OpenProcessToken #.
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000 #  Required to retrieve certain information about a process = see GetExitCodeProcess, GetPriorityClass, IsProcessInJob, QueryFullProcessImageName #. A handle that has the PROCESS_QUERY_INFORMATION access right is automatically granted PROCESS_QUERY_LIMITED_INFORMATION.  Windows Server 2003 and Windows XP:  This access right is not supported.
PROCESS_SET_INFORMATION = 0x0200 #    Required to set certain information about a process, such as its priority class = see SetPriorityClass #.
PROCESS_SET_QUOTA = 0x0100 #  Required to set memory limits using SetProcessWorkingSetSize.
PROCESS_SUSPEND_RESUME = 0x0800 # Required to suspend or resume a process.
PROCESS_TERMINATE = 0x0001 #  Required to terminate a process using TerminateProcess.
PROCESS_VM_OPERATION = 0x0008 #   Required to perform an operation on the address space of a process = see VirtualProtectEx and WriteProcessMemory #.
PROCESS_VM_READ = 0x0010 #    Required to read memory in a process using ReadProcessMemory.
PROCESS_VM_WRITE = 0x0020 #   Required to write to memory in a process using WriteProcessMemory.
SYNCHRONIZE = 0x00100000L #   Required to wait for the process to terminate using the wait functions.
PROCESS_ALL_ACCESS = PROCESS_CREATE_PROCESS | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_INFORMATION | PROCESS_SET_QUOTA | PROCESS_SUSPEND_RESUME | PROCESS_TERMINATE | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | SYNCHRONIZE

MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
MEM_RESET = 0x00080000
MEM_RESET_UNDO = 0x1000000
MEM_LARGE_PAGES = 0x20000000
MEM_PHYSICAL = 0x00400000
MEM_TOP_DOWN = 0x00100000

PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_GUARD = 0x100
PAGE_NOCACHE = 0x200
PAGE_WRITECOMBINE = 0x400

EXECUTE_IMMEDIATELY = 0x00000000
CREATE_SUSPENDED = 0x00000004
STACK_SIZE_PARAM_IS_A_RESERVATION = 0x00010000

OpenProcess = ctypes.windll.kernel32.OpenProcess
OpenProcess.restype = HANDLE
OpenProcess.argtypes = (DWORD, BOOL, DWORD)

VirtualAllocEx = ctypes.windll.kernel32.VirtualAllocEx
VirtualAllocEx.restype = LPVOID
VirtualAllocEx.argtypes = (HANDLE, LPVOID, DWORD, DWORD, DWORD)

ReadProcessMemory = ctypes.windll.kernel32.ReadProcessMemory
ReadProcessMemory.restype = BOOL
ReadProcessMemory.argtypes = (HANDLE, LPCVOID, LPVOID, DWORD, DWORD)

WriteProcessMemory = ctypes.windll.kernel32.WriteProcessMemory
WriteProcessMemory.restype = BOOL
WriteProcessMemory.argtypes = (HANDLE, LPVOID, LPCVOID, DWORD, DWORD)

CreateRemoteThread = ctypes.windll.kernel32.CreateRemoteThread
CreateRemoteThread.restype = HANDLE
CreateRemoteThread.argtypes = (HANDLE, LPSECURITY_ATTRIBUTES, DWORD, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD)

GetLastError = ctypes.windll.kernel32.GetLastError
GetLastError.restype = DWORD
GetLastError.argtypes = ()

GetModuleHandle = ctypes.windll.kernel32.GetModuleHandleA
GetModuleHandle.restype = HANDLE
GetModuleHandle.argtypes = (LPCTSTR,)

GetProcAddress = ctypes.windll.kernel32.GetProcAddress
GetProcAddress.restype = LPVOID
GetProcAddress.argtypes = (HANDLE, LPCTSTR)


def get_process_handle(dwProcessId, dwDesiredAccess, bInheritHandle=False):
    handle = OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId)
    if handle is None or handle == 0:
        raise Exception('Error: %s' % GetLastError())

    return handle

def allocate(hProcess, lpAddress, dwSize, flAllocationType, flProtect):
    lpBuffer = VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect)
    if lpBuffer is None or lpBuffer == 0:
        raise Exception('Error: %s' % GetLastError())

    return lpBuffer

def read_buffer(hProcess, lpBaseAddress, nSize):
    dwNumberOfBytesRead = ReadProcessMemory.argtypes[-1]()
    lpBuffer = ctypes.create_string_buffer(nSize)
    result = ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, ctypes.addressof(dwNumberOfBytesRead))
    if result is None or result == 0:
        raise Exception('Error: %s' % GetLastError())

    if dwNumberOfBytesRead.value != nSize:
        raise Exception('Read %s bytes when %s bytes should have been read' % (dwNumberOfBytesRead.value, nSize))

    return lpBuffer.raw

def write_buffer(hProcess, lpBaseAddress, lpBuffer, nSize):
    dwNumberOfBytesWritten = WriteProcessMemory.argtypes[-1]()
    result = WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, ctypes.addressof(dwNumberOfBytesWritten))
    if result is None or result == 0:
        raise Exception('Error: %s' % GetLastError())

    if dwNumberOfBytesWritten.value != nSize:
        raise Exception('Wrote %s bytes when %s bytes should have been written' % (dwNumberOfBytesWritten.value, nSize))

def allocate_and_write(hProcess, lpAddress, dwSize, flAllocationType, flProtect, lpBuffer):
    lpStartAddress = allocate(hProcess, lpAddress, dwSize, flAllocationType, flProtect)
    write_buffer(hProcess, lpStartAddress, lpBuffer, dwSize)

    return lpStartAddress

def create_thread(hProcess, lpStartAddress, dwStackSize=0, lpParameter=0, dwCreationFlags=EXECUTE_IMMEDIATELY, lpThreadId=0, lpSecurityDescriptor=0, bInheritHandle=False):
    ThreadAttributes = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), lpSecurityDescriptor, bInheritHandle)
    lpThreadAttributes = LPSECURITY_ATTRIBUTES(ThreadAttributes)
    handle = CreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId)

    if handle is None or handle == 0:
        raise Exception('Error: %s' % GetLastError())

    return handle

def inject_python(dwProcessId, port):
    var_size = ctypes.sizeof(ctypes.c_void_p)
    is_x86 = var_size == 4

    if is_x86:
        pack = functools.partial(struct.pack, 'I')
        prologue = '\x55\x89\xe5' # push ebp # mov ebp, esp
        epilogue = '\x5d\xc3' # pop ebp # retn

        opcode_move_ptr = '\xa3' # mov dword ptr [ptr], eax
        opcode_move_to_r0 = '\xa1' # mov eax, dword ptr [x]

    else:
        pack = functools.partial(struct.pack, 'Q')
        prologue = '\x48\x83\xec\x28' # sub rsp, 0x28
        epilogue = '\x48\x83\xc4\x28\xc3' # add rsp, 0x28 # ret

        opcode_move_ptr = '\x48\xa3' # mov qword ptr [ptr], rax
        opcode_move_to_r0 = '\x48\xa1' # mov rax, qword ptr [x]

    empty_variable = '\x00' * var_size
    opcode_call_r0 = '\xff\xd0' # call rax/eax
    
    hGetProcAddress = pack(GetProcAddress(GetModuleHandle('kernel32.dll'), 'GetProcAddress'))
    hLoadLibraryA = pack(GetProcAddress(GetModuleHandle('kernel32.dll'), 'LoadLibraryA'))

    hProcess = get_process_handle(dwProcessId, PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE)

    python_functions = [
        'Py_Initialize', 'PyImport_AddModule', 'PyImport_ImportModule',
        'PyObject_SetAttrString', 'Py_CompileString', 'PyModule_GetDict',
        'PyEval_EvalCode', 'PyDict_New', 'Py_Finalize'
    ]

    data = hGetProcAddress + hLoadLibraryA
    lpmain_module_offset = len(data)
    data += empty_variable
    lpcode_offset = len(data)
    data += empty_variable
    lpglobal_dict_offset = len(data)
    data += empty_variable
    lplocal_dict_offset = len(data)
    data += empty_variable

    python_function_base_offset = len(data)
    data += empty_variable * len(python_functions)
    data += 'python27.dll\x00'
    data += '\x00'.join(python_functions) + '\x00'

    python_code = 'rpyc.utils.server.ThreadedServer(rpyc.core.SlaveService, hostname="", port=%s, reuse_addr=True, ipv6=False, authenticator=None, registrar=None, auto_register=False).start()' % port
    misc_strings = [
        '__main__',
        'rpyc',
        'rpyc.core',
        'rpyc.utils.server',
        'injection',
        python_code
    ]
    data += '\x00'.join(misc_strings) + '\x00'
    lpDataBufferLocal = ctypes.create_string_buffer(data)
    lpDataBufferRemote = allocate_and_write(hProcess, 0, len(lpDataBufferLocal), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE, lpDataBufferLocal)
    code = ''

    func_address_map = {}

    def get_data_address(x): return pack(lpDataBufferRemote + data.index(x))
    def call_function(x): return opcode_move_to_r0 + func_address_map[x] + opcode_call_r0
    def move_r0_to_address(x): return opcode_move_ptr + x

    if is_x86:
        opcode_push_r0 = '\x50' # push rax/eax
        arg0_reg0 = arg1_reg0 = arg2_reg0 = opcode_push_r0

        opcode_push_ptr = '\xff\x35' # push dword ptr [x]
        def arg0_pointer(x): return opcode_push_ptr + x
        arg1_pointer = arg2_pointer = arg0_pointer

        opcode_push_imm = '\x68' # push x
        def arg0_imm(x): return opcode_push_imm + pack(x)
        arg1_imm = arg2_imm = arg0_imm

        def arg0_data_address(x): return opcode_push_imm + get_data_address(x)
        arg1_data_address = arg2_data_address = arg0_data_address

    else:
        arg0_reg0 = '\x48\x89\xc1'
        arg1_reg0 = '\x48\x89\xc2'
        arg2_reg0 = '\x49\x89\xc0'

        def arg0_pointer(x): return opcode_move_to_r0 + x + arg0_reg0
        def arg1_pointer(x): return opcode_move_to_r0 + x + arg1_reg0
        def arg2_pointer(x): return opcode_move_to_r0 + x + arg2_reg0

        opcode_move_imm_to_r1 = '\x48\xb9'
        def arg0_imm(x): return opcode_move_imm_to_r1 + pack(x)
        opcode_move_imm_to_r2 = '\x48\xba'
        def arg1_imm(x): return opcode_move_imm_to_r2 + pack(x)
        opcode_move_imm_to_r8 = '\x49\xb8'
        def arg2_imm(x): return opcode_move_imm_to_r8 + pack(x)

        def arg0_data_address(x): return opcode_move_imm_to_r1 + get_data_address(x)
        def arg1_data_address(x): return opcode_move_imm_to_r2 + get_data_address(x)
        def arg2_data_address(x): return opcode_move_imm_to_r8 + get_data_address(x)

    callGetProcAddress = opcode_move_to_r0 + get_data_address(hGetProcAddress) + opcode_call_r0
    callLoadLibraryA = opcode_move_to_r0 + get_data_address(hLoadLibraryA) + opcode_call_r0
    lpmain_module = pack(lpDataBufferRemote + lpmain_module_offset)
    lpcode = pack(lpDataBufferRemote + lpcode_offset)
    lpglobal_dict = pack(lpDataBufferRemote + lpglobal_dict_offset)
    lplocal_dict = pack(lpDataBufferRemote + lplocal_dict_offset)

    code += prologue

    for i, function in enumerate(python_functions):
        address = pack(lpDataBufferRemote + python_function_base_offset + (i*var_size))
        func_address_map[function] = address

        # GetProcProcess(LoadLibrary('python27.dll'), function)
        code += arg0_data_address('python27.dll') + callLoadLibraryA + \
                arg1_data_address(function) + arg0_reg0 + callGetProcAddress + \
                move_r0_to_address(address)

    # Py_Initialize();
    code += call_function('Py_Initialize')

    # main_module = PyImport_AddModule("__main__");
    code += arg0_data_address('__main__') + call_function('PyImport_AddModule') + \
            move_r0_to_address(lpmain_module)

    # PyImport_ImportModule("rpyc.core");
    code += arg0_data_address('rpyc.core') + call_function('PyImport_ImportModule')

    # PyImport_ImportModule("rpyc.utils.server");
    code += arg0_data_address('rpyc.utils.server') + call_function('PyImport_ImportModule')

    # PyObject_SetAttrString(main_module, "rpyc", PyImport_ImportModule("rpyc"));
    code += arg0_data_address('rpyc') + call_function('PyImport_ImportModule')
    code += arg2_reg0 + arg1_data_address('rpyc') + arg0_pointer(lpmain_module) + \
            call_function('PyObject_SetAttrString')

    # code = Py_CompileString("rpyc.utils.server.ThreadedServer(rpyc.core.SlaveService, hostname=\"\", port=%s, reuse_addr=True, ipv6=False, authenticator=None, registrar=None, auto_register=False).start()", "injection", Py_file_input);
    code += arg2_imm(0x00000100) + arg1_data_address('injection') + \
            arg0_data_address('rpyc.utils.server.ThreadedServer(rpyc.core.SlaveService') + \
            call_function('Py_CompileString') + move_r0_to_address(lpcode)

    # global_dict = PyModule_GetDict(main_module);
    code += arg0_pointer(lpmain_module) + call_function('PyModule_GetDict') + \
            move_r0_to_address(lpglobal_dict)

    # local_dict = PyDict_New();
    code += call_function('PyDict_New') + move_r0_to_address(lplocal_dict)

    # PyEval_EvalCode(code, global_dict, local_dict);
    code += arg2_pointer(lplocal_dict) + arg1_pointer(lpglobal_dict) + \
            arg0_pointer(lpcode) + call_function('PyEval_EvalCode')

    # Realistically, we will never make it here
    # Py_Finalize();
    code += call_function('Py_Finalize')

    code += epilogue

    lpCodeBufferLocal = ctypes.create_string_buffer(code)
    lpCodeBufferRemote = allocate_and_write(hProcess, 0, len(lpCodeBufferLocal), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE, lpCodeBufferLocal)

    thread_id = DWORD()
    create_thread(hProcess, lpCodeBufferRemote, lpThreadId=LPDWORD(thread_id))

    return thread_id

if __name__ == '__main__':
    import sys

    try:
        import rpyc

    except ImportError:
        print 'You must install the rpyc module in order to use this script'

    if len(sys.argv) >= 2:
        pid = sys.argv[1]

    else:
        print 'Usage:'
        print '\t%s PID [port]' % sys.argv[0]
        print
        print '32-bit python is required to inject into a 32-bit process'
        print '64-bit python is required to inject into a 64-bit process'
        sys.exit(1)

    if len(sys.argv) >= 3:
        port = int(sys.argv[2])

    else:
        port = 50000
        print 'Defaulting to port %s' % port

    if pid.startswith('0x'):
        pid = int(pid, 16)

    else:
        pid = int(pid)

    print 'Injecting python into PID %s so it listens on port %s' % (pid, port)
    print 'Thread ID: %s' % inject_python(pid, port)

