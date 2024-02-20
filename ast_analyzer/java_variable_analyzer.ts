/**
 *
 * The analyzer is capable of extracting undeclared variables from a given method.
 */

// Adjusted to collect all variables declared at the root level

export function extractVariableUsageReferences(node: any, methodNode: any) {
  const variableDeclarations = extractVariableDeclarations(node);
  const variableUsages = extractVariableUsagesFromMethod(methodNode);
  let declaredVariableUsages: Record<any, any> = {};
  // Iterate over variable usages to accumulate usage lines for declared variables
  variableUsages.forEach((usage) => {
    const declaration = variableDeclarations.find(
      (declaration) => declaration.name === usage.variableName
    );

    if (declaration) {
      // If the variable is declared, add or update the entry in declaredVariableUsages
      if (!declaredVariableUsages[usage.variableName]) {
        declaredVariableUsages[usage.variableName] = [usage.lineUsed];
      } else {
        declaredVariableUsages[usage.variableName].push(usage.lineUsed);
      }
    } else {
      // Optionally, handle undeclared variables (e.g., log or store them separately)
      console.log(
        `Undeclared variable found: ${usage.variableName} at line ${usage.lineUsed}`
      );
    }
  });

  return { variableDeclarations, variableUsages, declaredVariableUsages };
}
export function extractVariableDeclarations(node: any) {
  let variableDeclarations: { name: string; statement: string }[] = [];

  // Helper function to recursively traverse the AST

  function traverseAST(node: any, callback: (node: any) => void) {
    callback(node);
    Object.values(node).forEach((child) => {
      if (Array.isArray(child)) {
        child.forEach((childNode) => traverseAST(childNode, callback));
      } else if (child && typeof child === "object" && "!" in child) {
        traverseAST(child, callback);
      }
    });
  }

  // Function to process each node
  function processNode(node: any) {
    if (node["!"] === "com.github.javaparser.ast.body.VariableDeclarator") {
      const variableName = node.name.identifier; // Adjust based on actual structure
      // For the statement, you might need to reconstruct it from the node or parent node
      // This is a placeholder; actual implementation will depend on the AST structure
      const statement = reconstructStatement(node);

      variableDeclarations.push({ name: variableName, statement });
    }
  }

  // Function to reconstruct the statement from a variable declarator node
  // This is a conceptual function; actual implementation will depend on the AST structure
  function reconstructStatement(node: any): string {
    let statement = "";

    // Step 1: Determine the variable's type
    // This might involve simple types (e.g., int, String) or complex ones (e.g., List<String>)
    const type = reconstructType(node.type);

    // Step 2: Extract the variable name
    const variableName = node.name.identifier; // Assuming this is the correct path to the variable name

    // Step 3: Check if there's an initializer and reconstruct it
    let initializer = "";
    if (node.initializer) {
      // The initializer can be another expression that needs to be reconstructed
      initializer = " = " + reconstructInitializer(node.initializer);
    }

    // Combine the parts to form the statement
    statement = type + " " + variableName + initializer + ";";

    return statement;
  }

  function reconstructType(typeNode: any): string {
    if (!typeNode) return "UnknownType";

    // Adjusted handling for PrimitiveType
    if (typeNode["!"] === "com.github.javaparser.ast.type.PrimitiveType") {
      return typeNode.type; // Correctly use 'type' for PrimitiveType nodes
    }

    // Handle ClassOrInterfaceType, including generics
    if (
      typeNode["!"] === "com.github.javaparser.ast.type.ClassOrInterfaceType"
    ) {
      if (typeNode.typeArguments) {
        const baseType = typeNode.name.identifier;
        const typeArgs = typeNode.typeArguments.map(reconstructType).join(", ");
        return `${baseType}<${typeArgs}>`;
      }
      return typeNode.name.identifier;
    }

    // Handle ArrayType
    if (typeNode["!"] === "com.github.javaparser.ast.type.ArrayType") {
      const componentType = reconstructType(typeNode.componentType);
      return `${componentType}[]`;
    }

    // Add more cases as needed for other type structures

    return "ComplexType"; // Fallback for unhandled types
  }

  function reconstructInitializer(initializerNode: any): string {
    // Direct handling of literals
    if (initializerNode["!"] === "com.github.javaparser.ast.expr.LiteralExpr") {
      return initializerNode.value;
    }

    // Handling simple method calls as initializers
    if (
      initializerNode["!"] === "com.github.javaparser.ast.expr.MethodCallExpr"
    ) {
      const methodName = initializerNode.name.identifier;
      const args = initializerNode.arguments
        .map(reconstructInitializer)
        .join(", ");
      return `${methodName}(${args})`;
    }

    // Handling object creation (new expressions)
    if (
      initializerNode["!"] ===
      "com.github.javaparser.ast.expr.ObjectCreationExpr"
    ) {
      const typeName = reconstructType(initializerNode.type);
      const args = initializerNode.arguments
        .map(reconstructInitializer)
        .join(", ");
      return `new ${typeName}(${args})`;
    }

    // Handling array initializers
    if (
      initializerNode["!"] ===
      "com.github.javaparser.ast.expr.ArrayInitializerExpr"
    ) {
      const values = initializerNode.values
        .map(reconstructInitializer)
        .join(", ");
      return `{${values}}`;
    }

    // Add more cases as necessary for other types of initializers

    return "ComplexInitializer"; // Fallback for unhandled initializers
  }

  traverseAST(node, processNode);

  return variableDeclarations;
}

function extractVariableUsagesFromMethod(methodNode: any) {
  let variableUsages: { variableName: string; lineUsed: number }[] = [];

  // Helper function to recursively traverse the AST
  function traverseAST(node: any, callback: (node: any) => void) {
    callback(node);
    Object.values(node).forEach((child) => {
      if (Array.isArray(child)) {
        child.forEach((childNode) => traverseAST(childNode, callback));
      } else if (child && typeof child === "object" && "!" in child) {
        traverseAST(child, callback);
      }
    });
  }

  // Function to process each node and identify method call expressions
  function processNode(node: any) {
    if (node["!"] === "com.github.javaparser.ast.expr.MethodCallExpr") {
      // Initialize variableName with null to handle cases without scope
      let variableName = null;

      // Check if the method call has a scope, then extract the variable name
      if (node.scope && node.scope.name) {
        variableName = node.scope.name.identifier;
      }

      // Proceed only if variableName is found, indicating the method call is on a variable
      if (variableName) {
        variableUsages.push({
          variableName: variableName,
          lineUsed: node.range.beginLine, // Assuming 'range' provides the line number
        });
      }
    }
  }

  traverseAST(methodNode, processNode);

  return variableUsages;
}
