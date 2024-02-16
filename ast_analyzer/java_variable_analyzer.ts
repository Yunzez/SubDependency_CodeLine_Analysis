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
    // Placeholder for logic to reconstruct the statement from the node
    // This could involve accessing parent nodes or related parts of the AST
    return "variable declaration statement"; // Placeholder
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
