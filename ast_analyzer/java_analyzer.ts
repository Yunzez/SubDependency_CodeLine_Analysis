export const analyzeJava = (currentAst: any, filePath: string) => {
    const methodDeclarations = extractMethodDeclarations(currentAst);
    console.log("Method Declarations: ", methodDeclarations);

    const methodDetails = extractMethodDetails(currentAst, filePath);
    console.log("Method Details: ", methodDetails);
}

const extractMethodDeclarations = (node: any): any[] => {
    const methodDeclarations: any[] = [];

    if (node["!"] && node["!"] === "com.github.javaparser.ast.body.MethodDeclaration") {
        methodDeclarations.push(node);
    }

    // Recursively search for nested structures
    for (const key in node) {
        if (node[key] instanceof Array) {
            for (const childNode of node[key]) {
                methodDeclarations.push(...extractMethodDeclarations(childNode));
            }
        } else if (node[key] instanceof Object) {
            methodDeclarations.push(...extractMethodDeclarations(node[key]));
        }
    }

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
