import * as fs from "fs";
import * as path from "path";

export const serializeScope = (scope: any): string => {
  // Handle different types of scopes
  if (typeof scope === "object" && scope !== null) {
    if (scope.type === "NameExpr") {
      return scope.name.identifier; // For simple name expressions
    }
    // Add more conditions if there are other types of scopes
    return traverseArgumentNode(scope); // Fallback for complex scopes
  }
  return scope.toString(); // Fallback for primitive scope representations
};

export function countJavaFiles(dir: string): number {
  let count = 0;
  const files = fs.readdirSync(dir);

  for (const file of files) {
    const fullPath = path.join(dir, file);
    const stat = fs.statSync(fullPath);

    if (stat.isDirectory()) {
      count += countJavaFiles(fullPath); // Recurse into subdirectories
    } else if (fullPath.endsWith(".java")) {
      count++; // Found a .java file
    }
  }

  return count;
}

export const serializeArgument = (arg: any): string => {
  if (typeof arg === "object" && arg !== null) {
    return traverseArgumentNode(arg);
  } else {
    return arg.toString();
  }
};

export const traverseArgumentNode = (node: any): string => {
  switch (node["!"]) {
    case "com.github.javaparser.ast.expr.StringLiteralExpr":
      // Serialize string literals with quotes
      return `"${node.value}"`;

    case "com.github.javaparser.ast.expr.BooleanLiteralExpr":
      // Directly return the boolean value as a string
      return node.value.toString();

    case "com.github.javaparser.ast.expr.LiteralExpr":
      // Handle general literals (numbers, etc.)
      return node.value.toString();

    case "com.github.javaparser.ast.expr.ObjectCreationExpr":
      // Serialize object creation expressions
      const typeName = node.type.name.identifier;
      const args =
        node.arguments.length > 0
          ? "(" + node.arguments.map(serializeArgument).join(", ") + ")"
          : "";
      return `new ${typeName}${args}`;

    case "com.github.javaparser.ast.expr.MethodCallExpr":
      // Serialize method call expressions
      const methodName = node.name.identifier;
      const methodArgs =
        node.arguments.length > 0
          ? "(" + node.arguments.map(serializeArgument).join(", ") + ")"
          : "";
      const methodScope = node.scope
        ? traverseArgumentNode(node.scope) + "."
        : "";
      return `${methodScope}${methodName}${methodArgs}`;

    case "com.github.javaparser.ast.expr.NameExpr":
      // Serialize name expressions
      return node.name.identifier;

    case "com.github.javaparser.ast.expr.FieldAccessExpr":
      // Serialize field access expressions
      const fieldScope = traverseArgumentNode(node.scope);
      return `${fieldScope}.${node.name.identifier}`;

    case "com.github.javaparser.ast.expr.IntegerLiteralExpr":
      return node.value;

    case "com.github.javaparser.ast.expr.DoubleLiteralExpr":
      return node.value;

    case "com.github.javaparser.ast.expr.UnaryExpr":
      const operator = node.operator; // Adjust based on your AST structure
      const expression = traverseArgumentNode(node.expression);
      return `${operator}${expression}`;

    case "com.github.javaparser.ast.expr.BinaryExpr":
      const leftExpr = traverseArgumentNode(node.left);
      const rightExpr = traverseArgumentNode(node.right);
      const binaryOperator = node.operator; // Adjust based on your AST structure
      return `${leftExpr} ${binaryOperator} ${rightExpr}`;

    // Add more cases as needed for other specific node types

    default:
      // Placeholder for unhandled types
      return "[complex expression]";
  }
};

// find all ast path of the directory
export const findAstPaths = (astDirectroy: string, saveTo: string[]) => {
  fs.readdirSync(astDirectroy).forEach((dir: string) => {
    let fullPath = path.join(astDirectroy, dir);
    //   console.log(`Reading directory: ${fullPath}`);
    if (fs.statSync(fullPath).isFile()) {
      // Collect third-party AST files
      saveTo.push(fullPath);
    }
  });
};
