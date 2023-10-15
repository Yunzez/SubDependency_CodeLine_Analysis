import argparse
import ast
import json
import os
import importlib
import inspect
import textwrap # wrap text to correct indentation


def analyze_function(code, function_name):
    tree = ast.parse(code)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == function_name:
            return node.lineno, node.end_lineno
    return None, None

def recursive_analyze_function(code, function_name, result, depth=0, max_depth=10, processed=None, import_map=None):
    if processed is None:
        processed = set()

    if function_name in processed:
        print(f"Skipping already processed function {function_name}")
        return

    processed.add(function_name)

    try:
        start_line, end_line = analyze_function(code, function_name)
    except SyntaxError as e:
        print(f"Failed to parse code for function {function_name}: {e}")
        return

    if start_line is None:
        return

    print(f"Analyzing {function_name}, depth {depth}")  

    result['lines'] = f"{start_line} - {end_line}"
    result['internal_calls'] = []

    lines = code.split('\n')[start_line - 1:end_line]
    internal_code = '\n'.join(lines)
    try:
        tree = ast.parse(internal_code)
    except Exception as e:
        print(f"Failed to parse code for function {function_name}: {e}")
        return

    local_processed = set()  # To keep track of functions processed in this specific call

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            child_function_name = None
            if isinstance(func, ast.Attribute):
                if isinstance(func.value, ast.Name):
                    child_function_name = f"{func.value.id}.{func.attr}"
                else:
                    child_function_name = f"{ast.dump(func.value)}.{func.attr}"
            elif isinstance(func, ast.Name):
                child_function_name = func.id

            if child_function_name:
                # Check if function is in an imported module
                if child_function_name.split('.')[0] in import_map:
                    print(f"Skipping external function: {child_function_name}")
                    continue
                
                if child_function_name in local_processed:
                    continue  # Skip if already processed in this call

                local_processed.add(child_function_name)  # Mark as processed in this call

                internal_result = {'function': child_function_name}
                recursive_analyze_function(
                    code, child_function_name.split('.')[-1], internal_result, depth + 1, max_depth, processed, import_map)
                result['internal_calls'].append(internal_result)


def analyze_script_coverage(script_code, external_code_map):
    processed_functions = set()
    analysis_result = {
        'imported_modules': [],
        'external_calls': []
    }

    import_map = {}

    tree = ast.parse(script_code)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for n in node.names:
                import_map[n.name.split('.')[0]] = n.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module
            for n in node.names:
                import_map[n.name] = f"{module}.{n.name}"

        if isinstance(node, ast.Call):
            func = node.func
            package = None
            function_name = None
            if isinstance(func, ast.Attribute):
                if isinstance(func.value, ast.Name):
                    function_name = f"{func.value.id}.{func.attr}"
                    package = import_map.get(func.value.id)
            elif isinstance(func, ast.Name):
                function_name = func.id
                package = import_map.get(func.id)

            if function_name:
                if function_name in processed_functions:
                    continue  # Skip if already processed

                processed_functions.add(function_name)  # Mark as processed

                start_line, end_line = None, None
                details = {}
                
                if package is None:
                    print(f"Skipping analysis for built-in function {function_name}")
                    continue

                if package and package in external_code_map:
                    start_line, end_line = analyze_function(
                        external_code_map[package], function_name.split('.')[-1])
                    recursive_analyze_function(
                        external_code_map[package], function_name.split('.')[-1], details, import_map=import_map)

                analysis_result['external_calls'].append({
                    'function': function_name,
                    'line': node.lineno,
                    'package': package,
                    'lines_in_package': f"{start_line} - {end_line}" if start_line and end_line else None,
                    'details': details
                })

    with open('./python/analysis_result.json', 'w') as f:
        json.dump(analysis_result, f, indent=4)

# returns the path to the module if it exists, None otherwise


def get_module_path(module_name):
    try:
        module = importlib.import_module(module_name)
        if not hasattr(module, '__file__'):
            print(f"{module_name} is a built-in module, skipping.")
            return None
        module_path = inspect.getfile(module)
        return module_path
    except Exception as e:
        print(f"An error occurred: {e}")
        return None


def getImports(script_code):
    import_map = {}

    tree = ast.parse(script_code)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for n in node.names:
                import_map[n.name.split('.')[0]] = n.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module
            for n in node.names:
                import_map[n.name] = f"{module}.{n.name}"
    return import_map


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Analyze Python script for package usage.')
    parser.add_argument('file_path', type=str,
                        help='Path to the Python script to analyze')

    args = parser.parse_args()

    with open(args.file_path, 'r') as f:
        script_code = f.read()

    # analyze the script to get the list of imported modules
    import_map = getImports(script_code)

    # populate external_code_map based on the imported modules
    external_code_map = {}
    for module_name, full_module_name in import_map.items():
        module_path = get_module_path(module_name)
        if module_path:
            with open(module_path, 'r') as f:
                external_code_map[full_module_name] = f.read()

    analyze_script_coverage(script_code, external_code_map)
