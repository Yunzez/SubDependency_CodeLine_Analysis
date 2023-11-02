

import fs from "fs";
const functionLocationMap: Map<string, FunctionInfo> = new Map();
const callSet = new Set();
const functionSet = new Set();
const useSet = new Set();
type NodeType = {
  type: string;
  named: boolean;
  fields?: any;
  children?: any;
};

type FunctionInfo = {
  line: string;
  file: string;
};

export const findTypeNode = (
  node: any,
  typeName: string,
  onFound: (node: any) => void
): any => {
  if (node.type === typeName) {
    onFound(node);
  }
  for (const child of node.children || []) {
    findTypeNode(child, typeName, onFound);
  }
};

export const analyzeRust = (currentAst: any, path: string) => {
  // Initial tick for starting
  console.log("Gathering function calls...");

  let typeName = "call_expression";
  for (const fileNode of Object.entries(currentAst)) {
    findTypeNode(fileNode[1], typeName, (node: any) => {
      callSet.add(node);
    });
  }

  console.log(`Gathering function calls done. Total: ${callSet.size}`);

  console.log("Gathering use_declaration...");
  typeName = "use_declaration";
  for (const fileNode of Object.entries(currentAst)) {
    findTypeNode(fileNode[1], typeName, (node: any) => {
      useSet.add(node);
    });
  }

  console.log(`Gathering use_declaration done. Total: ${useSet.size}`);

  console.log("Gathering function_item...");
  typeName = "function_item";
  for (const fileNode of Object.entries(currentAst)) {
    findTypeNode(fileNode[1], typeName, (node: any) => {
      functionSet.add({ node, file: fileNode[0] });
    });
  }

  console.log(`Gathering function_item done. Total: ${functionSet.size}`);

  console.log("Processing function items...");
  functionSet.forEach(processFunctionItem);

  functionSet.forEach((node: any) => {
    findFunctionCallsInFunction(node);
  });

  console.log("Writing to file...");
  const writeMapToJsonFile = (map: Map<string, any>, filePath: string) => {
    const obj = Object.fromEntries(map);
    const json = JSON.stringify(obj, null, 2);
    fs.writeFileSync(filePath, json);
  };
  writeMapToJsonFile(functionCallsMap, "./functionCallsMap.json");

  console.log("All tasks completed!");
};

const functionCallsMap: Map<string, { functions: any[]; self: any }> =
  new Map();

export const findFunctionCallsInFunction = (functionNode: any) => {
  const node = functionNode.node;
  const file = functionNode.file;
  // console.log('findFunctionCallsInFunction', node)
  const identifierNode = node.children.find(
    (child: any) => child.type === "identifier"
  );
  if (!identifierNode) {
    console.log("Identifier not found for function_item");
    return;
  }

  // Extract function name and location info from the node
  const functionName = identifierNode.text;
  const parentFunctionInfo = functionLocationMap.get(functionName);
  const functionCalls: any[] = [];

  findTypeNode(node, "call_expression", (callNode: any) => {
    const identifierNode = callNode.children.find(
      (child: any) =>
        child.type === "identifier" || child.type === "field_expression"
    );
    if (!identifierNode) {
      console.log("call_expressio Identifier not found for call_expression");
      return;
    }
    let originalName = identifierNode.text;
    let calledFunctionName = identifierNode.text;
    if (calledFunctionName.startsWith("self.")) {
      calledFunctionName = calledFunctionName.substring(5); // Remove 'self.'
    }
    const line = `${callNode.start_position.row}-${callNode.end_position.row}`;

    const functionInfo = functionLocationMap.get(calledFunctionName);
    console.log("functionInfo", originalName, functionInfo);
    let functionFileLine = "";
    if (functionInfo) {
      functionFileLine = functionInfo.line;
      functionCalls.push({
        function_name: originalName,
        used_location_file_name: file,
        function_file_name: functionInfo ? functionInfo.file : "unknown",
        used_location_line: line,
        function_file_line: functionFileLine,
      });
    }
  });

  functionCallsMap.set(functionName, {
    functions: functionCalls,
    self: parentFunctionInfo,
  });
};

export const processFunctionItem = (functionNode: any) => {
  const node = functionNode.node;
  const file = functionNode.file;

  const identifierNode = node.children.find(
    (child: any) => child.type === "identifier"
  );
  if (!identifierNode) {
    console.log("Identifier not found for function_item");
    return;
  }

  // Extract function name and location info from the node
  const functionName = identifierNode.text;
  const line = `${node.start_position.row}-${node.end_position.row}`;

  functionLocationMap.set(functionName, { line, file });
};
