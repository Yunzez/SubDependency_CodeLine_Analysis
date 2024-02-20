import * as fs from "fs";
import { serializeArgument, serializeScope } from "./java_analyzer_utils";
import ImportAnalyzer from "./java_import_analyzer";
import {
  extractVariableDeclarations,
  extractVariableUsageReferences,
} from "./java_variable_analyzer";
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
    // * extractMethodDetails produce information of the all the function of the file being process currently
    const methodDetails = extractMethodDetails(currentAst, filePath, basicInfo);

    // * a recursive call to extractImportStatements to get all the import statements
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
  const importStatements = extractImportStatements(currentAst);
  const methodDeclarations = extractMethodDeclarations(currentAst);
  const variableDeclarations = extractVariableDeclarations(currentAst);
  // console.log(`Found ${methodDeclarations.length} method declarations`);
  // localResolveVariableSource(importStatements, variableDeclarations);
  // Perform analysis specific to local ASTs
  const localMethodCalls = extractLocalMethodCalls(
    currentAst,
    thirdPartyMethodDetails
  );
  console.log(`Extracted local method calls from ${filePath}`);

  // Append the method calls to a JSON file
  return { [filePath]: localMethodCalls };
};

// const localResolveVariableSource = (
//   importStatement: string[],
//   variableDeclarations: {
//     name: string;
//     statement: string;
//   }[]
// ) => {
//   let resolvedVariableDeclarations = [];
//   for (let variable of variableDeclarations) {
//     // console.log("variable", variable.name);
//     // console.log("statement", variable.statement);
//     if (variable.name.includes(".")) {
//       let variableParts = variable.name.split(".");
//       if (importStatement.includes(variableParts[0])) {
//         resolvedVariableDeclarations.push(variable);
//       }
//     } else {
//       resolvedVariableDeclarations.push(variable);
//     }
//   }
//   return resolvedVariableDeclarations;
// };

const extractLocalMethodCalls = (
  node: any,
  thirdPartyMethodDetails: any
): any => {
  let localMethodCalls: {
    functionName: any;
    function_expression: string;
    line: string;
    downstream_info: any;
  }[] = [];

  const traverseNode = (currentNode: any) => {
    if (
      currentNode["!"] &&
      currentNode["!"] === "com.github.javaparser.ast.expr.MethodCallExpr"
    ) {
      const methodName = currentNode.name.identifier;
      const methodCallLine = extractMethodCallLine(currentNode);
      const firstPart = methodCallLine.split(".")[0];

      // ! precheck if the method is part of the package we are looking for
      // ! disable the check when encouter uncertainity
      let downstream_info = thirdPartyMethodDetails[methodName] ?? {};
      if (thirdPartyMethodDetails[methodName]) {
        const className =
          downstream_info.self_information.dependencyInfo.className;
        let cleanedName = className.replace("Optional[", "").replace("]", "");
        if (!cleanedName.includes(firstPart)) {
          downstream_info = {};
        }
      }
      localMethodCalls.push({
        functionName: methodName,
        function_expression: methodCallLine,
        line: `${currentNode.range.beginLine}-${currentNode.range.endLine}`,
        downstream_info: downstream_info,
      });
    }

    Object.values(currentNode).forEach((childNode) => {
      if (
        childNode instanceof Array ||
        (childNode instanceof Object && "!" in childNode)
      ) {
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

/**
 * * This function extracts method declarations from the AST and returns the root node of each method.
 */
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

/**
 * * This function analyze one method from the root node .
 * * we compare the function in the "Node" with the internalMethods set'
 * * it recersuively look for nested structures
 */
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

    const { variableDeclarations, variableUsages, declaredVariableUsages } =
      extractVariableUsageReferences(node, method);
    console.log(`Extracted undeclared variables from ${functionName}`);
    methodDetails[functionName] = {
      external_functions: external,
      internal_functions: internal,
      // variableDeclarations: variableDeclarations,
      allVariableUsage: variableUsages,
      declaredVariableUsages: declaredVariableUsages,
      self_information: {
        line: `${method.range.beginLine}-${method.range.endLine}`, // Assuming line numbers are stored in `range`
        file_name: filePath,
        dependencyInfo: {
          groupId: basicInfo.groupId,
          artifactId: basicInfo.artifactId,
          version: basicInfo.version,
          className: basicInfo.className,
        },
      },
    };
  }

  return methodDetails;
};
