
import ida_hexrays
import ida_kernwin
import idc
import idautils

def process_sscanf_callers(instr, sscanf):
    func = ida_hexrays.decompile(instr)

    # Error prone, better would be to filter func.body.treeitems
    node = func.body.find_closest_addr(instr)
    if node is None:
        return
    if node.op != ida_hexrays.cot_call:
        return
    node = node.to_specific_type
    if node.x.op != ida_hexrays.cot_obj:
        return
    if node.x.obj_ea != sscanf:
        return

    num_args = len(list(node.a)) - 2

    parent = func.body.find_parent_of(node)
    if parent is None:
        # Should never happen ?
        return

    grandparent = func.body.find_parent_of(parent)

    comparand = None
    if parent.op == ida_hexrays.cit_expr and grandparent.op == ida_hexrays.cit_block:
        pass
    else:
        if parent.op == ida_hexrays.cot_asg:
            parent.to_specific_type.x

        if parent.op == ida_hexrays.cot_eq:
            parent = parent.to_specific_type
            if parent.y.op != ida_hexrays.cot_num:
                print('Not supporting comparisons against anything but an num node')
                return

            else:
                comparand = parent.y.n._value

        elif parent.op == ida_hexrays.cit_if:
            comparand = 'nonzero'

    if comparand is None:
        print("The sscanf call at 0x%08x is worth looking at, no comparisons were found despite %d arguments" % (instr, num_args))

    elif comparand == 'nonzero':
        print("The sscanf call at 0x%08x is worth looking at, there is only a comparison against being non-zero and there are %d arguments" % (instr, num_args))

    else:
        if comparand < num_args:
            print("The sscanf call at 0x%08x is worth looking at, there is a comparison against %d but there are %d arguments" % (instr, comparand, num_args))

def find_sscanf_vulns():
    idc.Wait()
    sscanf = idc.LocByName('_sscanf')
    if sscanf == idc.BADADDR:
        print("sscanf not found")
        return

    for caller in idautils.CodeRefsTo(sscanf, False):
        process_sscanf_callers(caller, sscanf)

    if ida_kernwin.cvar.batch:
        idc.Exit(0)


if __name__ == '__main__':
    find_sscanf_vulns()



