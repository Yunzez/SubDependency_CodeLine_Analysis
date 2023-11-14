import * as fs from 'fs';


export const analyzeJava = (currentAst: any, filePath: string) => {
    console.log(`Analyzing AST node from file: ${filePath}`, currentAst);

    const methodDetails = extractMethodDetails(currentAst, filePath);
    console.log(`Extracted method details from ${filePath}`);

    // Append the method details to a JSON file
    appendToJSONFile('java_ast_functionmap.json', methodDetails);
}

// Incremental JSON file writing
const appendToJSONFile = (filename: string, data: any) => {
    let existingData = {};
    if (fs.existsSync(filename)) {
        existingData = JSON.parse(fs.readFileSync(filename, 'utf8'));
    }
    
    const updatedData = { ...existingData, ...data };
    fs.writeFileSync(filename, JSON.stringify(updatedData, null, 2));
    console.log(`Data appended to ${filename}`);
}

const extractMethodDeclarations = (node: any, methodDeclarations: any[] = []) => {
    if (node["!"] && node["!"] === "com.github.javaparser.ast.body.MethodDeclaration") {
        methodDeclarations.push(node);
    }

    Object.values(node).forEach(childNode => {
        if (childNode instanceof Array || childNode instanceof Object) {
            extractMethodDeclarations(childNode, methodDeclarations);
        }
    });

    return methodDeclarations;
}

const extractFunctionCalls = (node: any): string[] => {
    const functionCalls: string[] = [];

    // Check if the current node represents a function call
    if (node["!"] && node["!"] === "com.github.javaparser.ast.expr.MethodCallExpr") {
        functionCalls.push(node.name.identifier); // Assuming the function name is stored in `name.identifier`
    }

    // Recursively search for nested structures
    for (const key in node) {
        if (node[key] instanceof Array) {
            for (const childNode of node[key]) {
                functionCalls.push(...extractFunctionCalls(childNode));
            }
        } else if (node[key] instanceof Object) {
            functionCalls.push(...extractFunctionCalls(node[key]));
        }
    }

    return functionCalls;
};

const extractMethodDetails = (node: any, filePath: string): any => {
    const methodDetails: Record<any, any> = {};

    const methodDeclarations = extractMethodDeclarations(node);

    for (const method of methodDeclarations) {
        const functionName = method.name.identifier; // Assuming the method name is stored in `name.identifier`
        const functionCalls = extractFunctionCalls(method);

        methodDetails[functionName] = {
            "functions": functionCalls,
            "self": {
                "line": `${method.range.beginLine}-${method.range.endLine}`, // Assuming line numbers are stored in `range`
                "file": filePath
            }
        };
    }

    return methodDetails;
};
