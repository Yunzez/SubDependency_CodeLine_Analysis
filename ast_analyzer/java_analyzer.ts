import * as fs from "fs";
import { serializeArgument, serializeScope } from "./java_analyzer_utils";

export const analyzeJava = (
  currentAst: any,
  filePath: string,
  isThirdParty: boolean
) => {
  console.log(`Analyzing AST node from file: ${filePath}`, currentAst);

  if (isThirdParty) {
    const methodDetails = extractMethodDetails(currentAst, filePath);
    console.log(`Extracted method details from ${filePath}`);

    // Append the method details to a JSON file
    appendToJSONFile("java_ast_third_party_analysis.json", methodDetails);
  } else {
    // Analysis logic specific to local ASTs
    const localInfo = analyzeLocalJava(currentAst, filePath);
    appendToJSONFile("java_ast_local_file_analysis.json", localInfo);
  }
};

export const analyzeLocalJava = (currentAst: any, filePath: string) => {
  // Load third-party method details as a reference
  let thirdPartyMethodDetails = {};
  if (fs.existsSync("java_ast_third_party_analysis.json")) {
    thirdPartyMethodDetails = JSON.parse(
      fs.readFileSync("java_ast_third_party_analysis.json", "utf8")
    );
  }

  // Perform analysis specific to local ASTs
  const localMethodCalls = extractLocalMethodCalls(
    currentAst,
    thirdPartyMethodDetails
  );
  console.log(`Extracted local method calls from ${filePath}`);

  // Append the method calls to a JSON file
  return { [filePath]: localMethodCalls };
};

const extractLocalMethodCalls = (
  node: any,
  thirdPartyMethodDetails: any
): any => {
  let localMethodCalls: {
    methodName: any;
    methodCallLine: string;
    line: string;
    thirdPartyInfo: any;
  }[] = [];

  const traverseNode = (currentNode: any) => {
    if (
      currentNode["!"] &&
      currentNode["!"] === "com.github.javaparser.ast.expr.MethodCallExpr"
    ) {
    //   console.log("find method call");
      const methodName = currentNode.name.identifier;
      const methodCallLine = extractMethodCallLine(currentNode);

    //   if (thirdPartyMethodDetails[methodName]) {
        localMethodCalls.push({
          methodName: methodName,
          methodCallLine: methodCallLine,
          line: `${currentNode.range.beginLine}-${currentNode.range.endLine}`,
          thirdPartyInfo: thirdPartyMethodDetails[methodName],
        });
    //   }
    }

    Object.values(currentNode).forEach((childNode) => {
      if (childNode instanceof Array || childNode instanceof Object) {
        traverseNode(childNode);
      }
    });
  };

  traverseNode(node);

  return localMethodCalls;
};

export const extractMethodCallLine = (methodCallNode: any): string => {
    let methodCallLine = '';

    // Check if the method call has a scope and serialize it
    if (methodCallNode.scope) {
        methodCallLine += serializeScope(methodCallNode.scope) + '.';
    }

    // Add the method name
    methodCallLine += methodCallNode.name.identifier;

    // Serialize arguments
    methodCallLine += '(' + methodCallNode.arguments.map(serializeArgument).join(", ") + ')';
    return methodCallLine;
};

// Incremental JSON file writing
const appendToJSONFile = (filename: string, data: any) => {
  let existingData = {};
  if (fs.existsSync(filename)) {
    existingData = JSON.parse(fs.readFileSync(filename, "utf8"));
  }

  const updatedData = { ...existingData, ...data };
  fs.writeFileSync(filename, JSON.stringify(updatedData, null, 2));
  console.log(`Data appended to ${filename}`);
};

const extractMethodDeclarations = (
  node: any,
  methodDeclarations: any[] = []
) => {
  if (
    node["!"] &&
    node["!"] === "com.github.javaparser.ast.body.MethodDeclaration"
  ) {
    methodDeclarations.push(node);
  }

  Object.values(node).forEach((childNode) => {
    if (childNode instanceof Array || childNode instanceof Object) {
      extractMethodDeclarations(childNode, methodDeclarations);
    }
  });

  return methodDeclarations;
};

const extractFunctionCalls = (
  node: any,
  functionSets: Set<string> = new Set<string>()
): string[] => {
  // Check if the current node represents a function call
  if (
    node["!"] &&
    node["!"] === "com.github.javaparser.ast.expr.MethodCallExpr"
  ) {
    functionSets.add(node.name.identifier); // Add to set
  }

  // Recursively search for nested structures
  for (const key in node) {
    if (node[key] instanceof Array) {
      for (const childNode of node[key]) {
        extractFunctionCalls(childNode, functionSets); // Pass the set to the recursive call
      }
    } else if (node[key] instanceof Object) {
      extractFunctionCalls(node[key], functionSets); // Pass the set to the recursive call
    }
  }

  // Convert the set to an array when the recursion completes
  if (functionSets.size > 0) {
    return Array.from(functionSets);
  } else {
    return [];
  }
};

const extractMethodDetails = (node: any, filePath: string): any => {
  const methodDetails: Record<any, any> = {};

  const methodDeclarations = extractMethodDeclarations(node);

  for (const method of methodDeclarations) {
    const functionName = method.name.identifier; // Assuming the method name is stored in `name.identifier`
    const functionCalls = extractFunctionCalls(method);

    methodDetails[functionName] = {
      functions: functionCalls,
      self: {
        line: `${method.range.beginLine}-${method.range.endLine}`, // Assuming line numbers are stored in `range`
        file: filePath,
      },
    };
  }

  return methodDetails;
};
