import ast from "../ast_generator/ast.json";
import node_type from "../ast_generator/node-types.json";
const astTree = new Map();

const callSet = new Set();
const functionSet = new Set();
const useSet = new Set();
/**
 *  @named field indicates whether a particular node type corresponds to a named rule in the grammar or an anonymous rule. Named rules typically represent more semantically meaningful constructs in the language, while anonymous rules might represent more syntactic or structural details.
 *  @fields field is an array of strings, each of which is the name of a field in the node type. The order of the fields is significant, and corresponds to the order of the fields in the grammar rule that the node type represents.
 *  @children  provides information about the child nodes that a particular node type can have according to the grammar. It specifies the types of child nodes, and whether they are required or optional, as well as if there can be multiple instances of them.
 *  @children -
 *   @multiple : a boolean indicating whether the node type can have multiple instances of the specified child node types.
 *   @required : indicating whether the child nodes are required for this node type according to the grammar
 *   @types : an array containing the possible types of child nodes. Each type is represented by an object detailing the type of node
 */

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

type FunctionNode = {
  node: any;
  file: string;
};

const functionLocationMap: Map<string, FunctionInfo> = new Map();

const functionTreeMap: Map<string, any> = new Map();

const nodeTypeMap = new Map<string, NodeType>();

const mapAst = () => {
  // console.log(node_type)
};

const findTypeNode = (
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

const init = (): void => {
  console.log("init");

  console.log("gathering function calls....");
  let typeName = "call_expression";
  for (const fileNode of Object.entries(ast)) {
    const fileName = fileNode[0];
    const fileValue = fileNode[1];
    findTypeNode(fileValue, typeName, (node: any) => {
      //   console.log("add node:", node);
      callSet.add(node);
      //   console.log("end -------");
    });
  }

  console.log("callSet size: ", callSet.size);
  console.log("gathering function calls, done");

  console.log("gathering use_declaration....");
  typeName = "use_declaration";
  let functionItemNode = null;
  for (const fileNode of Object.entries(ast)) {
    const fileName = fileNode[0];
    const fileValue = fileNode[1];
    findTypeNode(fileValue, typeName, (node: any) => {
      //   console.log("add node:", node);
      useSet.add(node);
      //   console.log("end -------");
    });
  }

  console.log("useSet size: ", useSet.size);
  console.log("gathering use_declaration, done");

  console.log("gathering function_item....");
  typeName = "function_item";

  for (const fileNode of Object.entries(ast)) {
    const fileName = fileNode[0];
    const fileValue = fileNode[1];
    findTypeNode(fileValue, typeName, (node: any) => {
      //   console.log("add node:", node);
      functionSet.add({ node, file: fileName });
      //   console.log("end -------");
    });
  }

  console.log("useSet size: ", functionSet.size);
  console.log("gathering use_declaration, done");

  // Process function items to populate functionLocationMap

  functionSet.forEach(processFunctionItem);

  // Process call expressions to find function locations
  // callSet.forEach(processCallExpression);

  // New code to find function calls within each function
  functionSet.forEach((node: any) => {
    findFunctionCallsInFunction(node);
  });

//   console.log(functionLocationMap);
  console.log(functionCallsMap);
};

const functionCallsMap: Map<string, any[]> = new Map();

const findFunctionCallsInFunction = (functionNode: any) => {
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
    let originalName = identifierNode.text
    let calledFunctionName = identifierNode.text;
    if (calledFunctionName.startsWith('self.')) {
      calledFunctionName = calledFunctionName.substring(5);  // Remove 'self.'
    }
    const line = `${callNode.start_position.row}-${callNode.end_position.row}`;

    const functionInfo = functionLocationMap.get(calledFunctionName);
    console.log("functionInfo", originalName, functionInfo);
    let functionFileLine = "";
    if (functionInfo) {
      functionFileLine = functionInfo.line;
    }

    functionCalls.push({
      function_name: originalName,
      used_location_file_name: file,
      function_file_name: functionInfo ? functionInfo.file : "unknown",
      used_location_line: line,
      function_file_line: functionFileLine,
    });
  });

  functionCallsMap.set(functionName, functionCalls);
};

const processFunctionItem = (functionNode: any) => {
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

init();

mapAst();
