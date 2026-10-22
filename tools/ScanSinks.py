"""Emit structured Ghidra evidence for dangerous sinks and input APIs."""

import json

SINKS = ("strcpy", "strncpy", "sprintf", "snprintf", "system", "popen", "printf")
INPUT_APIS = ("recv", "recvfrom", "read", "fgets", "gets", "getenv", "cgi", "nvram_get", "nvram_safe_get", "socket", "accept")


def _references_to(function):
    return currentProgram.getReferenceManager().getReferencesTo(function.getEntryPoint())


def _caller_records(function):
    callers = []
    seen = set()
    for reference in _references_to(function):
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
    iterator = function_manager.getFunctions(True)
    while iterator.hasNext():
        function = iterator.next()
        name = function.getName()
        if not any(sink in name.lower() for sink in SINKS):
            continue
        callers = _caller_records(function)
        payload = {
            "sink_function": name,
            "sink_address": str(function.getEntryPoint()),
            "callers": [item["function"] for item in callers],
            "call_sites": [item["call_site"] for item in callers],
            "input_sources": input_sources,
        }
        print("EVIDENCE_JSON|" + json.dumps(payload, ensure_ascii=False))


run()
