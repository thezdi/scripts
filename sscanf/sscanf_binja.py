
from binaryninja import binaryview
from binaryninja import SymbolType
from binaryninja import MediumLevelILOperation
from binaryninja import VariableSourceType

def process_sscanf_caller_instructions(bv, insn):
    if len(insn.params) < 2:
        print("Don't have the minimun number of sscanf arguments at %08x" % insn.address)
        return

    args = insn.params[2:]

    if len(insn.vars_written) != 1:
        print('Expected only one var write at %08x' % insn.address)
        return

    result = insn.vars_written[0]
    if result.var.source_type != VariableSourceType.RegisterVariableSourceType:
        print('Expected this to return a register at %08x' % insn.address)
        return

    tracked_vars = set([result])
    comparands = set()
    while len(tracked_vars) > 0:
        temp_vars = tracked_vars
        tracked_vars = set()
        for tracked_var in temp_vars:
            for use in insn.function.ssa_form.get_ssa_var_uses(tracked_var):
                if use.operation == MediumLevelILOperation.MLIL_SET_VAR_SSA:
                    tracked_vars.add(use.dest)

                elif use.operation == MediumLevelILOperation.MLIL_IF:
                    if use.condition.operation.name.startswith('MLIL_CMP'):
                        if use.condition.left.operation == MediumLevelILOperation.MLIL_VAR_SSA and use.condition.left.src == tracked_var:
                            comparison = use.condition.right
                        elif use.condition.right.operation == MediumLevelILOperation.MLIL_VAR_SSA and use.condition.right.src == tracked_var:
                            comparison = use.condition.left

                        # We don't care if we're only looking at a subset of the return value because it's only required to be an int
                        elif use.condition.left.operation == MediumLevelILOperation.MLIL_VAR_SSA_FIELD and use.condition.left.src == tracked_var:
                            comparison = use.condition.right
                        elif use.condition.right.operation == MediumLevelILOperation.MLIL_VAR_SSA_FIELD and use.condition.right.src == tracked_var:
                            comparison = use.condition.left

                        else:
                            print('WTF is being compared at %08x' % use.address)
                            continue

                        if comparison.operation != MediumLevelILOperation.MLIL_CONST:
                            print('WTF is this comparison operation at %08x' % use.address)
                            continue

                        comparands.add(comparison.value.value)

                    else:
                        print('WTF is this at %08x' % use.address)
                        continue

    start = 'The sscanf call at %08x in %s' % (insn.address, insn.function.llil.source_function.name)
    end = '%d arguments' % len(args)
    if len(comparands) == 0:
        print('%s is worth looking at, there are no comparisons despite %s' % (start, end))
        return

    for comparand in comparands:
        if comparand < len(args):
            print('%s may be worth looking at, there is a comparison to %d but there are %s' % (start, comparand, end))

def find_sscanf_vulns(bv):
    sscanf_symbol = bv.get_symbol_by_raw_name('_sscanf')
    if sscanf_symbol is None:
        print("sscanf not found")
        return

    if sscanf_symbol.type != SymbolType.ImportedFunctionSymbol:
        print("sscanf is not an imported function")
        return None

    sscanf = bv.get_function_at(sscanf_symbol.address)
    # We get a list of Functions here instead of the instructions making the call, which means we may have dupes
    for caller in set(sscanf.callers):
        for insn in caller.mlil.ssa_form.instructions:
            if insn.operation == MediumLevelILOperation.MLIL_CALL_SSA:
                if insn.dest.value.value == sscanf.start:
                    process_sscanf_caller_instructions(bv, insn)

def run(bv):
    bv.update_analysis_and_wait()

    find_sscanf_vulns(bv)

def main():
    import sys

    input_filename = sys.argv[1]
    bv = binaryview.BinaryViewType.get_view_of_file(input_filename, update_analysis=False)
    if bv == None:
        print("[!] Failed to load file: ", input_filename)
        return

    run(bv)

if __name__ == '__main__':
    main()

