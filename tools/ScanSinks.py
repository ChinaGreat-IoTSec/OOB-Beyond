"""Small Ghidra post-script that emits discovered dangerous sink names."""

from ghidra.program.model.listing import Function


SINKS = ("strcpy", "strncpy", "sprintf", "system", "popen", "printf")


def run():
    function_manager = currentProgram.getFunctionManager()
    iterator = function_manager.getFunctions(True)
    while iterator.hasNext():
        function = iterator.next()
        name = function.getName()
        if any(sink in name.lower() for sink in SINKS):
            print("SINK|%s|%s" % (name, function.getEntryPoint()))


run()
