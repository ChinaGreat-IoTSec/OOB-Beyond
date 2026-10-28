"""Emit structured Ghidra evidence for dangerous sinks and input APIs."""

import json
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.data import Array

SINKS = ("strcpy", "strncpy", "sprintf", "snprintf", "system", "popen", "printf")
INPUT_APIS = ("recv", "recvfrom", "read", "fgets", "gets", "getenv", "cgi", "nvram_get", "nvram_safe_get", "socket", "accept")


def _name(function):
    if function.isThunk():
        resolved = function.getThunkedFunction(True)
        if resolved:
            function = resolved
    return function.getName()


def _argument(node, index, high_function, depth=0):
    result = {"index": index, "basis": "bounded intraprocedural P-code"}
    if node is None or depth >= 12:
        return result
    operation = node.getDef()
    if operation and operation.getMnemonic() in ("COPY", "CAST"):
        return _argument(operation.getInput(0), index, high_function, depth + 1)
    if node.isConstant():
        value = long(node.getOffset()) & ((1 << (node.getSize() * 8)) - 1)
        result["constant"] = value
        address = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value)
        memory = currentProgram.getMemory()
        block = memory.getBlock(address)
        if block and block.isInitialized() and not block.isWrite():
            for offset in range(4096):
                location = address.add(offset)
                if not block.contains(location):
                    break
                if memory.getByte(location) == 0:
                    result["string_length"] = offset
                    result["basis"] = "NUL-terminated bytes in read-only memory"
                    break
    if operation and operation.getMnemonic() == "CALL":
        source = currentProgram.getFunctionManager().getFunctionAt(operation.getInput(0).getAddress())
        if source and _name(source) in ("getenv", "nvram_get", "nvram_safe_get"):
            result["source"] = _name(source)
    if operation and operation.getMnemonic() == "PTRSUB":
        base = operation.getInput(0)
        offset = operation.getInput(1)
        stack_register = currentProgram.getCompilerSpec().getStackPointer()
        register = currentProgram.getRegister(base.getAddress(), base.getSize()) if base.isRegister() else None
        if offset.isConstant() and register == stack_register and stack_register is not None:
            signed = long(offset.getOffset()) & ((1 << (offset.getSize() * 8)) - 1)
            if signed & (1 << (offset.getSize() * 8 - 1)):
                signed -= 1 << (offset.getSize() * 8)
            for symbol in high_function.getLocalSymbolMap().getSymbols():
                if not isinstance(symbol.getDataType(), Array) or not symbol.getStorage().isStackStorage():
                    continue
                if signed == symbol.getStorage().getStackOffset():
                    result["capacity"] = symbol.getDataType().getLength()
                    result["storage"] = "stack"
                    result["basis"] = "decompiler array at exact stack object base; inferred capacity"
                    break
    return result


def _references_to(function):
    return currentProgram.getReferenceManager().getReferencesTo(function.getEntryPoint())


def _caller_records(function):
    callers = []
    seen = set()
    for reference in _references_to(function):
        if not reference.getReferenceType().isCall():
            continue
        caller = currentProgram.getFunctionManager().getFunctionContaining(reference.getFromAddress())
        caller_name = caller.getName() if caller else "<external>"
        call_site = str(reference.getFromAddress())
        key = (caller_name, call_site)
        if key not in seen:
            seen.add(key)
            callers.append({"function": caller_name, "call_site": call_site})
    return callers


def _input_sources(function_manager):
    sources = []
    iterator = function_manager.getFunctions(True)
    while iterator.hasNext():
        function = iterator.next()
        name = function.getName().lower()
        if any(api in name for api in INPUT_APIS):
            sources.append({
                "function": function.getName(),
                "address": str(function.getEntryPoint()),
                "callers": _caller_records(function),
            })
    return sources


def run():
    function_manager = currentProgram.getFunctionManager()
    input_sources = _input_sources(function_manager)
    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)
    cache = {}
    try:
        iterator = function_manager.getFunctions(True)
        while iterator.hasNext():
            monitor.checkCancelled()
            function = iterator.next()
            name = _name(function)
            if name not in SINKS:
                continue
            for caller_record in _caller_records(function):
                arguments = []
                gaps = ["Indirect calls, cross-function propagation, memory writes and guard/path constraints are not resolved"]
                address = currentProgram.getAddressFactory().getAddress(caller_record["call_site"])
                caller = function_manager.getFunctionContaining(address)
                if caller and caller.isThunk():
                    continue
                try:
                    key = str(caller.getEntryPoint()) if caller else None
                    if key and key not in cache:
                        if len(cache) >= 200:
                            gaps.append("Caller decompilation budget exhausted")
                        else:
                            result = decompiler.decompileFunction(caller, 30, monitor)
                            cache[key] = result.getHighFunction() if result.decompileCompleted() else None
                    high = cache.get(key)
                    if high:
                        operations = high.getPcodeOps(address)
                        while operations.hasNext():
                            operation = operations.next()
                            if operation.getMnemonic() == "CALL" and operation.getInput(0).getAddress() == function.getEntryPoint():
                                arguments = [_argument(operation.getInput(index), index - 1, high)
                                             for index in range(1, operation.getNumInputs())]
                                break
                    if not arguments:
                        gaps.append("Call arguments unavailable or decompilation incomplete")
                except Exception as error:
                    gaps.append("Argument extraction failed: " + str(error))
                payload = {
                    "sink_function": name,
                    "sink_address": str(function.getEntryPoint()),
                    "callers": [caller_record["function"]],
                    "call_sites": [caller_record["call_site"]],
                    "input_sources": input_sources,
                    "arguments": arguments,
                    "analysis_gaps": gaps,
                }
                print("EVIDENCE_JSON|" + json.dumps(payload, ensure_ascii=False))
    finally:
        decompiler.dispose()
    print("EVIDENCE_COMPLETE|1")


run()
