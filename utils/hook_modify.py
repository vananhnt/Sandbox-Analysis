from pycparser import parse_file, c_ast
from pathlib import Path 
import re

class CapemonHook:
    """ Extract hook implementation from CAPEMON """
    CAPEMON = './capemon_v0'
    
    def extract_capemon_hookdef(capemon_fdl=CAPEMON):
        """ Return list of hooked apis and hooked api hookdef content"""
        hooked_apis = []
        hookdefs = []
        for file in list(Path(capemon_fdl).rglob("*.c")):
            hooked_apis += CapemonHook.__extract_function_definitions(file)
        for hookdef in hooked_apis:
            hookdefs.append(hookdef['api'])
        hookdefs = sorted(hookdefs)
        return hookdefs, hooked_apis
    
    # Basic regex to capture function definitions (not declarations)
    HOOKDEF_REGEX = re.compile(
        r'''
        HOOKDEF\(\s*
        (?P<return_type>[^,]+),\s*
        (?P<calling_convention>[^,]+),\s*
        (?P<function_name>\w+),\s*
        (?P<params>.*?)         # Capture the remaining parameters (multiline)
        \)\s*\{                 # Match closing ) and opening {
        ''',
        re.DOTALL | re.VERBOSE
    )

    def __extract_function_definitions(file_path):
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            code = f.read()
        matches = CapemonHook.HOOKDEF_REGEX.finditer(code)
        hook_list = []
        for match in matches:
            start = match.start()
            body_start = code.find('{', match.end() - 1)

            # Step 2: Brace counting to get full function body
            brace_count = 1
            i = body_start + 1
            while i < len(code):
                if code[i] == '{':
                    brace_count += 1
                elif code[i] == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        body_end = i + 1
                        break
                i += 1

            # Extract function parts
            function_body = code[start:body_end]
            hook_list.append({
                'api': match.group('function_name'),
                'params': match.group('params').strip(),
                'body': function_body.strip()
            })
           
        return hook_list
    
    def __find_all_c_files(root_dir):
        return list(Path(root_dir).rglob("*.c"))
          
if __name__ == "__main__":
    CapemonHook.extract_capemon_hookdef(capemon_fdl='./capemon')