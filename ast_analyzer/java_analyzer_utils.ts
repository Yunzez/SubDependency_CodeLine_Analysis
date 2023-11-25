
export const serializeScope = (scope: any): string => {
    // Handle different types of scopes
    if (typeof scope === 'object' && scope !== null) {
        if (scope.type === 'NameExpr') {
            return scope.name.identifier;  // For simple name expressions
        }
        // Add more conditions if there are other types of scopes
        return traverseArgumentNode(scope); // Fallback for complex scopes
    }
    return scope.toString();  // Fallback for primitive scope representations
};

export const serializeArgument = (arg: any): string => {
    if (typeof arg === 'object' && arg !== null) {
        // Handle different types of argument nodes
        return traverseArgumentNode(arg);
    } else {
        // Handle primitives directly
        return arg.toString();
    }
};

export const traverseArgumentNode = (node: any): string => {
    // Check the type of the node and handle accordingly
    if (node.type === 'Literal') {
        return node.value;
    } else if (node.type === 'ObjectCreationExpr') {
        // For object creation, include the type and possibly the arguments
        const args = node.arguments ? '(' + node.arguments.map(serializeArgument).join(", ") + ')' : '';
        return 'new ' + node.typeName.identifier + args;
    } else if (node.type === 'MethodCallExpr') {
        // For method calls, include the method name and the arguments
        const methodName = node.name.identifier;
        const args = node.arguments ? '(' + node.arguments.map(serializeArgument).join(", ") + ')' : '';
        return methodName + args;
    } else if (node.type === 'NameExpr') {
        // For simple name expressions, return the identifier
        return node.name.identifier;
    } else if (node.type === 'FieldAccessExpr') {
        // For field access, return the full expression
        return node.scope + '.' + node.name.identifier;
    }
    // Add more cases as needed for other node types

    return '[complex expression]';
};
