
from idaapi import get_imagebase
from idc import GetInputFile
from idc import BADADDR
from idc import Name
from idc import LocByName
from idc import Dword
from idc import Qword
from idautils import DataRefsFrom

SERVICE_TABLE_NAME_SYMBOL_MAP = {
    'ntoskrnl.exe' : ('KiServiceTable', 'KiServiceLimit'),
    'win32k.sys' : ('W32pServiceTable', 'W32pServiceLimit'),
}
SERVICE_TABLE_NAME_BASE_MAP = {
    'ntoskrnl.exe' : 0,
    'win32k.sys' : 0x1000,
}

def _get_service_table_info():
    name = GetInputFile().lower()
    if name not in SERVICE_TABLE_NAME_SYMBOL_MAP:
        return None

    stride = 8
    table_name, limit_name = SERVICE_TABLE_NAME_SYMBOL_MAP[name]
    table_address = LocByName(table_name)
    if table_address == BADADDR:
        table_name = '_' + table_name
        limit_name = '_' + limit_name
        table_address = LocByName(table_name)
        stride = 4
        if table_address == BADADDR:
            print 'table address failure'
            return None

    limit_address = LocByName(limit_name)
    limit = Dword(limit_address)
    base_id = SERVICE_TABLE_NAME_BASE_MAP[name]
    offset_base = 0

    if stride == 8:
        for x in DataRefsFrom(table_address):
            # Ideally we would test out the reference here
            # There is a chance IDA made a mistake as it seems to treat the
            # contents of the table as code when it contains 4-byte offsets
            break

        else:
            stride  = 4
            offset_base = get_imagebase()

    return table_address, limit, stride, base_id, offset_base

def enumerate_service_table():
    table_info = _get_service_table_info()
    if table_info is None:
        return

    table_start, limit, stride, base_id, offset_base = table_info
    table_end = table_start + limit * stride

    if stride == 4:
        getter = Dword

    else:
        getter = Qword

    for syscall_id, table_offset in enumerate(range(table_start, table_end, stride), base_id):
        function_offset = getter(table_offset)
        if function_offset == 0:
            continue

        function_address = function_offset + offset_base

        yield syscall_id, function_address
        
def print_service_table():
    for syscall_id, function_address in enumerate_service_table():
        function_name = Name(function_address)
        print '%04x - %s' % (syscall_id, function_name)

print_service_table()

