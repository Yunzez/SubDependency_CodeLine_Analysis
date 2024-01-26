import * as fs from "fs";
import { serializeArgument, serializeScope } from "./java_analyzer_utils";

export const analyzeJava = (
  currentAst: any,
  filePath: string,
  className: string,
  isThirdParty: boolean
) => {
  console.log(`Analyzing AST node from file: ${filePath}`);
  console.log(`------------------------------------------`);
  if (isThirdParty) {
    const methodDetails = extractMethodDetails(currentAst, filePath, className);
    console.log(`Extracted method details from ${filePath}`);

    // Append the method details to a JSON file
    appendToJSONFile("java_ast_third_party_analysis.json", methodDetails);
  } else {
    // const methodDetails = extractMethodDetails(currentAst, filePath, className);
    // console.log("local file method details: ", methodDetails)
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
    //  console.log("find method call");
      const methodName = currentNode.name.identifier;
      const methodCallLine = extractMethodCallLine(currentNode);

    //  if (thirdPartyMethodDetails[methodName]) {
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
  console.log("data: ", data)
  const updatedData = { ...existingData, ...data };
  fs.writeFileSync(filename, JSON.stringify(data, null, 2));
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
  internalMethods: Set<string>,
  externalFunctionCalls: Set<string> = new Set<string>(),
  internalFunctionCalls: Set<string> = new Set<string>()
): { external: string[], internal: string[] } => {
  if (
    node["!"] &&
    node["!"] === "com.github.javaparser.ast.expr.MethodCallExpr"
  ) {
    const methodName = node.name.identifier;

    // Check if the method is internal
    if (internalMethods.has(methodName)) {
      internalFunctionCalls.add(methodName); // Add to internal calls set
    } else {
      externalFunctionCalls.add(methodName); // Add to external calls set
    }
  }

  // Recursively search for nested structures
  for (const key in node) {
    if (node[key] instanceof Array) {
      for (const childNode of node[key]) {
        extractFunctionCalls(childNode, internalMethods, externalFunctionCalls, internalFunctionCalls);
      }
    } else if (node[key] instanceof Object) {
      extractFunctionCalls(node[key], internalMethods, externalFunctionCalls, internalFunctionCalls);
    }
  }

  return {
    external: Array.from(externalFunctionCalls),
    internal: Array.from(internalFunctionCalls)
  };
};


const extractMethodDetails = (node: any, filePath: string, className: string): any => {
  const methodDetails: Record<any, any> = {};

  const methodDeclarations = extractMethodDeclarations(node);
  console.log(`Found ${methodDeclarations.length} method declarations`)
  console.log(methodDeclarations)
  // console.log(methodDeclarations)
  const internalMethods = new Set(methodDeclarations);
  for (const method of methodDeclarations) {
    const functionName = method.name.identifier; // Assuming the method name is stored in `name.identifier`
    const { external, internal } = extractFunctionCalls(method, internalMethods);
    

    methodDetails[functionName] = {
      external_functions: external,
      internal_functions: internal,
      self: {
        line: `${method.range.beginLine}-${method.range.endLine}`, // Assuming line numbers are stored in `range`
        file: filePath,
        className: className,
      },
    };
  }

  return methodDetails;
};
