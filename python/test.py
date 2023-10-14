import argparse
import ast
import json
import os
import importlib
import inspect

def analyze_function(code, function_name):
    tree = ast.parse(code)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == function_name:
            return node.lineno, node.end_lineno
    return None, None

def analyze_script_coverage(script_code, external_code_map):
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
                start_line, end_line = None, None
                if package and package in external_code_map:
                    start_line, end_line = analyze_function(
                        external_code_map[package], function_name.split('.')[-1])

                analysis_result['external_calls'].append({
                    'function': function_name,
                    'line': node.lineno,
                    'package': package,
                    'lines_in_package': f"{start_line} to {end_line}" if start_line and end_line else None
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

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Analyze Python script for package usage.')
    parser.add_argument('file_path', type=str, help='Path to the Python script to analyze')

    args = parser.parse_args()

    with open(args.file_path, 'r') as f:
        script_code = f.read()

    # analyze the script to get the list of imported modules
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

    # populate external_code_map based on the imported modules
    external_code_map = {}
    for module_name, full_module_name in import_map.items():
        module_path = get_module_path(module_name)
        if module_path:
            with open(module_path, 'r') as f:
                external_code_map[full_module_name] = f.read()

    analyze_script_coverage(script_code, external_code_map)
