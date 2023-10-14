import ast
import argparse
import json

def analyze_script_coverage(code):
    tree = ast.parse(code)
    analysis_result = {
        'imported_modules': [],
        'external_calls': []
    }

    for node in ast.walk(tree):
        # Capture import statements
        if isinstance(node, ast.Import):
            for n in node.names:
                analysis_result['imported_modules'].append(n.name)
        elif isinstance(node, ast.ImportFrom):
            module = node.module
            for n in node.names:
                analysis_result['imported_modules'].append(f"{module}.{n.name}")

        # Capture external calls
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute):
                if isinstance(func.value, ast.Name):
                    analysis_result['external_calls'].append({
                        'function': f"{func.value.id}.{func.attr}",
                        'line': node.lineno
                    })
                else:
                    analysis_result['external_calls'].append({
                        'function': f"{ast.dump(func.value)}.{func.attr}",
                        'line': node.lineno
                    })
            elif isinstance(func, ast.Name):
                analysis_result['external_calls'].append({
                    'function': func.id,
                    'line': node.lineno
                })

    # Write to JSON file
    with open('analysis_result.json', 'w') as f:
        json.dump(analysis_result, f, indent=4)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Analyze Python script for package usage.')
    parser.add_argument('file_path', type=str, help='Path to the Python script to analyze')

    args = parser.parse_args()

    with open(args.file_path, 'r') as f:
        code = f.read()

    analyze_script_coverage(code)
