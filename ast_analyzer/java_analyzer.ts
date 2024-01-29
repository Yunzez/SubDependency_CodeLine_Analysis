import * as fs from "fs";
import { serializeArgument, serializeScope } from "./java_analyzer_utils";
import ImportAnalyzer from "./java_import_analyzer";

/**
 * * This function analyzes ONE Java Abstract Syntax Tree (AST).
 *
 * @param {any} currentAst - The AST to analyze.
 * @param {string} filePath - The path to the Java file.
 * @param {Record<string, string>} basicInfo - Basic information about the Java file.
 * @param {boolean} isThirdParty - Whether the Java file is a third-party file.
 * @param {boolean} analyzeImport - Whether to analyze import statements.
 * @param {string} outputFile - The name of the output file.
 * @returns {Promise<void>}
 */
export const analyzeJava = async (
  currentAst: any,
  filePath: string,
  basicInfo: Record<string, string>,
  isThirdParty: boolean,
  analyzeImport: boolean = false,
  outputFile: string = isThirdParty
    ? "java_ast_third_party_analysis.json"
    : "java_ast_local_file_analysis.json"
): Promise<void> => {
  console.log(`Analyzing AST node from file: ${filePath}`, basicInfo);
  console.log(`------------------------------------------`);
  if (isThirdParty) {
    const methodDetails = extractMethodDetails(currentAst, filePath, basicInfo);
    const importStatements = extractImportStatements(currentAst);
    console.log(`Found ${importStatements.length} external import statements`);
    console.log(importStatements);
    console.log(`Extracted method details from ${filePath}`);

    console.log("Analyzing imports: ", importStatements);

    const importAnalyzer = new ImportAnalyzer();
    const fileName = filePath.split("/")[filePath.split("/").length - 1];

    if (analyzeImport) {
      await importAnalyzer.analyzeImport(
        basicInfo.groupId,
        basicInfo.artifactId,
        basicInfo.version,
        importStatements,
        fileName
      );
    }

    // Append the method details to a JSON file
    appendToJSONFile(outputFile, methodDetails);
    console.log("output to", outputFile);
  } else {
    // const methodDetails = extractMethodDetails(currentAst, filePath, className);
    // console.log("local file method details: ", methodDetails)
    // Analysis logic specific to local ASTs
    const localInfo = analyzeLocalJava(currentAst, filePath);
    appendToJSONFile(outputFile, localInfo);
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
  let methodCallLine = "";

  // Check if the method call has a scope and serialize it
  if (methodCallNode.scope) {
    methodCallLine += serializeScope(methodCallNode.scope) + ".";
  }

  // Add the method name
  methodCallLine += methodCallNode.name.identifier;

  // Serialize arguments
  methodCallLine +=
    "(" + methodCallNode.arguments.map(serializeArgument).join(", ") + ")";
  return methodCallLine;
};

// Incremental JSON file writing
const appendToJSONFile = (filename: string, data: any) => {
  let existingData = {};
  if (fs.existsSync(filename)) {
    existingData = JSON.parse(fs.readFileSync(filename, "utf8"));
  }
  // console.log("data: ", data)
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

const extractFullImportPath = (node: any): string => {
  if (node.qualifier) {
    return extractFullImportPath(node.qualifier) + "." + node.identifier;
  } else {
    return node.identifier;
  }
};

const extractImportStatements = (
  node: any,
  importStatements: string[] = []
): string[] => {
  if (
    node["!"] &&
    node["!"] === "com.github.javaparser.ast.ImportDeclaration"
  ) {
    const importPath = extractFullImportPath(node.name);
    // importStatements.push(importPath);

    const firstSegment = importPath.split(".")[0];
    if (firstSegment !== "java") {
      importStatements.push(importPath);
    }
  }

  // Recursively search for nested structures
  Object.values(node).forEach((childNode) => {
    if (childNode instanceof Array || childNode instanceof Object) {
      extractImportStatements(childNode, importStatements);
    }
  });

  return importStatements;
};

const extractFunctionCalls = (
  node: any,
  internalMethods: Set<string>,
  externalFunctionCalls: Record<string, string> = {},
  internalFunctionCalls: Record<string, string> = {}
): { external: Record<string, string>; internal: Record<string, string> } => {
  if (
    node["!"] &&
    node["!"] === "com.github.javaparser.ast.expr.MethodCallExpr"
  ) {
    const methodName = node.name.identifier;
    const scope = node.scope ? extractFullScope(node.scope) : "";
    const fullMethodCall = scope ? `${scope}.${methodName}` : methodName;

    // Check if the method is internal
    if (internalMethods.has(methodName)) {
      internalFunctionCalls[methodName] = fullMethodCall;
    } else {
      externalFunctionCalls[methodName] = fullMethodCall;
    }
  }

  // Recursively search for nested structures
  for (const key in node) {
    if (node[key] instanceof Array) {
      for (const childNode of node[key]) {
        extractFunctionCalls(
          childNode,
          internalMethods,
          externalFunctionCalls,
          internalFunctionCalls
        );
      }
    } else if (node[key] instanceof Object) {
      extractFunctionCalls(
        node[key],
        internalMethods,
        externalFunctionCalls,
        internalFunctionCalls
      );
    }
  }

  return {
    external: externalFunctionCalls,
    internal: internalFunctionCalls,
  };
};

const extractFullScope = (node: any): string => {
  if (!node) {
    return "";
  }

  switch (node["!"]) {
    case "com.github.javaparser.ast.expr.FieldAccessExpr":
      // Recursively get the scope for field access
      const fieldScope = node.scope ? extractFullScope(node.scope) : "";
      const fieldName =
        node.name && node.name.identifier ? node.name.identifier : "";
      return fieldScope ? `${fieldScope}.${fieldName}` : fieldName;

    case "com.github.javaparser.ast.expr.NameExpr":
    case "com.github.javaparser.ast.expr.ThisExpr":
      // Directly return the identifier for simple names and 'this' expressions
      return node.name && node.name.identifier ? node.name.identifier : "this";

    case "com.github.javaparser.ast.expr.SimpleName":
      // Handle simple names
      return node.identifier ? node.identifier : "";

    default:
      // Fallback for other or unknown types of expressions
      return "";
  }
};

const extractMethodDetails = (
  node: any,
  filePath: string,
  basicInfo: Record<string, string>
): any => {
  const methodDetails: Record<any, any> = {};

  const methodDeclarations = extractMethodDeclarations(node);
  console.log(`Found ${methodDeclarations.length} method declarations`);
  // console.log(methodDeclarations)
  // console.log(methodDeclarations)
  const internalMethods = new Set(methodDeclarations);
  for (const method of methodDeclarations) {
    const functionName = method.name.identifier; // Assuming the method name is stored in `name.identifier`
    const { external, internal } = extractFunctionCalls(
      method,
      internalMethods
    );

    methodDetails[functionName] = {
      external_functions: external,
      internal_functions: internal,
      self: {
        line: `${method.range.beginLine}-${method.range.endLine}`, // Assuming line numbers are stored in `range`
        file: filePath,
        dependencyInfo: {
          groupId: basicInfo.groupId,
          artifactId: basicInfo.artifactId,
          version: basicInfo.version,
        },
      },
    };
  }

  return methodDetails;
};
