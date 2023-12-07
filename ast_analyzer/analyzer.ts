import ast_rust from "../rust/ast_generator/ast.json";
// import ast_java from "../java/ast_generator/ast.json";
// rust: ../rust/ast_generator/ast.json
// java: ../java/ast_generator/ast.json
import fs from "fs";
import ProgressBar from "progress";
import { analyzeRust } from "./rust_analyzer";
import { analyzeJava } from "./java_analyzer";
import path from "path";
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

const init = async (): Promise<void> => {
  const fs = require("fs");
  const { parser } = require("stream-json");
  const { streamValues } = require("stream-json/streamers/StreamValues");

  const { prompt } = require("enquirer");

  const typeResponse = await prompt({
    type: "select",
    name: "fileFormat",
    message: "Choose the format of the file:",
    choices: ["rust", "java", "js", "python", "go", "c++", "other"],
  });

  console.log(`You selected: ${typeResponse.fileFormat}`);

  const response = await prompt({
    type: "input",
    name: "filePath",
    message: `please input your ast file path:`,
  });

  const type = typeResponse.fileFormat;
  switch (type) {
    case "rust":
      let currentAst = undefined;
      if (response.filePath) {
        currentAst = JSON.parse(fs.readFileSync(response.filePath, "utf8"));
      }

      if (!currentAst) {
        currentAst = ast_rust;
      }
      analyzeRust(currentAst, response.filePath);
      break;

    case "java":
      const AST_DIRECTORY = "../asts/";
      const LOCAL_AST_DIRECTORY = "../asts/main";
      let thirdPartyAsts: string[] = [];
      let localAsts: string[] = [];
      // Step 1: Collecting AST Files
      fs.readdirSync(AST_DIRECTORY).forEach((dir: string) => {
        let fullPath = path.join(AST_DIRECTORY, dir);
        console.log(`Reading directory: ${fullPath}`);
        if (fs.statSync(fullPath).isFile()) {
          // Collect third-party AST files
          thirdPartyAsts.push(fullPath);
        }
      });

      fs.readdirSync(LOCAL_AST_DIRECTORY).forEach((dir: string) => {
        let fullPath = path.join(LOCAL_AST_DIRECTORY, dir);
        console.log(`Reading directory: ${fullPath}`);
        if (fs.statSync(fullPath).isFile()) {
          // Collect third-party AST files
          localAsts.push(fullPath);
        }
      });

      console.log(`Found ${thirdPartyAsts.length} third-party AST files`);
      console.log(`Found ${localAsts.length} local AST files`);

      // * Step 2: Processing AST Files

      // ! if third party analysis or local analysis json exist, delete it first
      if (fs.existsSync("java_ast_third_party_analysis.json")) {
        fs.unlinkSync("java_ast_third_party_analysis.json");
      }

      if (fs.existsSync("java_ast_local_file_analysis.json")) {
        fs.unlinkSync("java_ast_local_file_analysis.json");
      }
      // Process Third-Party ASTs
      console.log("Processing Third-Party ASTs");
      thirdPartyAsts.forEach((astFilePath) => {
        const astContent = JSON.parse(fs.readFileSync(astFilePath, "utf8"));
        const className = astContent.className;
        console.log("Class Name:", className)
        analyzeJava(astContent, astFilePath, className, true); // Differentiate mode
      });

      // Process Local ASTs
      console.log("Processing Local ASTs");
      localAsts.forEach((astFilePath) => {
        const astContent = JSON.parse(fs.readFileSync(astFilePath, "utf8"));
        const className = astContent.className;
        console.log("Class Name:", className)
        analyzeJava(astContent, astFilePath, className, false); // Add a mode parameter
      });

      break;
    default:
      console.log("not supported yet");
      break;
  }
};

init();

mapAst();
