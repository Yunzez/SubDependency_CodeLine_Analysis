import ast_rust from "../rust/ast_generator/ast.json";
// import ast_java from "../java/ast_generator/ast.json";
// rust: ../rust/ast_generator/ast.json
// java: ../java/ast_generator/ast.json
import fs from "fs";
import ProgressBar from "progress";
import { analyzeRust } from "./rust_analyzer";
import { analyzeJava } from "./java_analyzer";
import path from "path";
import { countJavaFiles, findAstPaths } from "./java_analyzer_utils";

/* example command line usage:
 * node analyzer.js
 * java                                              -> fileFormat
 * ../asts/                                          -> localAstDirectory
 * ../asts/main                                      -> thirdPartyAstDirectory
 * ../java_ast_local_file_analysis.json              -> localAnalysisOutputDir
 * ../asts/main/java_ast_third_party_analysis.json   -> thirdPartyAnalysisOutputDir
 */
const init = async (): Promise<void> => {
  let fileFormat = process.argv[2];
  let localAstDirectory = process.argv[3];
  let thirdPartyAstDirectory = process.argv[4];
  let localAnalysisOutputDir = process.argv[5];
  let thirdPartyAnalysisOutputDir = process.argv[6];
  let recursiveAnalysis = process.argv[6];

  const fs = require("fs");
  const { parser } = require("stream-json");
  const { streamValues } = require("stream-json/streamers/StreamValues");

  const { prompt } = require("enquirer");

  let typeResponse = null;
  if (fileFormat == null) {
    typeResponse = await prompt({
      type: "select",
      name: "fileFormat",
      message: "Choose the format of the file:",
      choices: ["java", "rust", "js", "python"],
    });
    fileFormat = typeResponse.fileFormat;
    console.log(`You selected: ${typeResponse.fileFormat}`);
  }

  if (recursiveAnalysis == null) {
    typeResponse = await prompt({
      type: "select",
      name: "recursiveAnalysis",
      message: "Do you want to recursively analyze the ASTs?",
      choices: ["true", "false"],
    });
    recursiveAnalysis = typeResponse.recursiveAnalysis ?? "true";
    console.log(`You selected: ${typeResponse.recursiveAnalysis}`);
  }

  const response = await prompt({
    type: "input",
    name: "filePath",
    message: `please input your ast file path:`,
  });

  switch (fileFormat) {
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
      const AST_DIRECTORY = thirdPartyAstDirectory ?? "../asts/";
      const LOCAL_AST_DIRECTORY = localAstDirectory ?? "../asts/main";
      let recursive = false;

      if (recursiveAnalysis != null) {
        recursive = recursiveAnalysis == "true" ? true : false;
      }

      let thirdPartyAsts: string[] = [];
      let localAsts: string[] = [];
      // Step 1: Collecting AST Files
      findAstPaths(AST_DIRECTORY, thirdPartyAsts);
      findAstPaths(LOCAL_AST_DIRECTORY, localAsts);

      console.log(`Found ${thirdPartyAsts.length} third-party AST files`);
      console.log(`Found ${localAsts.length} local AST files`);

      // * Step 2: Processing AST Files

      // ! if third party analysis or local analysis json exist, delete it first
      localAnalysisOutputDir =
        localAnalysisOutputDir ?? "./java_ast_local_file_analysis.json";

      thirdPartyAnalysisOutputDir =
        thirdPartyAnalysisOutputDir ?? "./java_ast_third_party_analysis.json";

      if (fs.existsSync(thirdPartyAnalysisOutputDir)) {
        fs.unlinkSync(thirdPartyAnalysisOutputDir);
      }

      if (fs.existsSync(localAnalysisOutputDir)) {
        fs.unlinkSync(localAnalysisOutputDir);
      }
      // Process Third-Party ASTs
      console.log("Processing Third-Party ASTs");
      const completePromises = thirdPartyAsts.map(async (astFilePath) => {
        const astContent = JSON.parse(fs.readFileSync(astFilePath, "utf8"));
        const basicInfo = {
          filePath: astFilePath,
          className: astContent.className,
          groupId: astContent.groupId,
          artifactId: astContent.artifactId,
          version: astContent.version,
        };
        const className = astContent.className;
        console.log("Class Name:", className, basicInfo);

        return analyzeJava(astContent, astFilePath, basicInfo, true, recursive); // is third party, and analyze import
      });

      // ! wait for all the promises to complete
      await Promise.all(completePromises);
      console.log("Finished processing third-party ASTs");
      console.log("Gather meta data from third party ASTs");

      await collectMetaInfo(thirdPartyAnalysisOutputDir);

      // Process Local ASTs
      console.log("Processing Local ASTs");
      localAsts.forEach((astFilePath) => {
        const astContent = JSON.parse(fs.readFileSync(astFilePath, "utf8"));
        const className = { className: astContent.className };
        console.log("Class Name:", className);
        analyzeJava(astContent, astFilePath, className, false, false); // not third party, and do not analyze import
      });

      const javaFileCount = countJavaFiles("./decompiled");
      console.log(`Found ${javaFileCount} Java files in decompiled directory`);
      break;
    default:
      console.log("not supported yet");
      break;
  }
};

const collectMetaInfo = async (astFilePath: string) => {
  if (!fs.existsSync(astFilePath)) {
    console.log(`AST file not found: ${astFilePath}`);
    return;
  }

  const functionsRequiredInfo = gatherFunctionsCall(astFilePath);
  await processMetaAstData("./subAst/output");
  // gatherFunctionMetaData(functionsRequiredInfo);
};

const gatherFunctionsCall = (astFilePath: string) => {
  const astContent = JSON.parse(fs.readFileSync(astFilePath, "utf8"));
  const functionsRequiredInfo: string[] = [];
  for (const [key, value] of Object.entries(astContent)) {
    const astValue = value as { external_functions: Record<string, string> };
    if (astValue.external_functions) {
      // Get all the values from the external_functions object and add to the array
      functionsRequiredInfo.push(...Object.values(astValue.external_functions));
    } else {
      console.log(`External functions not found in ${key}`);
    }
  }

  functionsRequiredInfo.filter((func) => {
    // Define patterns for system calls
    const systemPatterns = ["System.", "Thread.", "Objects."];

    // Check if the function call starts with any of the system patterns
    const isSystemCall = systemPatterns.some((pattern) =>
      func.startsWith(pattern)
    );

    // Check if the function call is an internal call (no dot notation)
    const isInternalCall = !func.includes(".");

    // Filter out system calls and internal calls
    return !isSystemCall && !isInternalCall;
  });

  console.log("functionsRequiredInfo:", functionsRequiredInfo);
  return functionsRequiredInfo;
};

const processMetaAstData = async (astDirectory: string) => {
  const astFiles = fs.readdirSync(astDirectory);
  const allPath: string[] = [];

  const findAllJsonFiles = (dirPath: string, arrayOfFiles: string[] = []) => {
    const files = fs.readdirSync(dirPath);

    files.forEach((file) => {
      const filePath = path.join(dirPath, file);
      if (fs.statSync(filePath).isDirectory()) {
        arrayOfFiles = findAllJsonFiles(filePath, arrayOfFiles);
      } else if (file.endsWith(".json")) {
        arrayOfFiles.push(filePath);
      }
    });

    return arrayOfFiles;
  };

  const jsonFiles = findAllJsonFiles(astDirectory);

  const completePromises = jsonFiles.map(async (dir: string) => {
    if (fs.statSync(dir).isFile()) {
      const astContent = JSON.parse(fs.readFileSync(dir, "utf8"));
      const basicInfo = {
        filePath: dir,
        className: astContent.className,
        groupId: astContent.groupId,
        artifactId: astContent.artifactId,
        version: astContent.version,
      };
      console.log(`Processing file: ${dir}`);
      return analyzeJava(
        astContent,
        dir,
        basicInfo,
        true,
        false,
        "metaAst.json"
      );
    }
  });

  await Promise.all(completePromises);
  console.log("All AST files processed.");
};

const gatherFunctionMetaData = (functionInfo: string[]) => {
  const functionMetaData: Record<string, any> = {};
  const bar = new ProgressBar(
    "Analyzing function calls [:bar] :percent :etas",
    {
      complete: "=",
      incomplete: " ",
      width: 50,
      total: functionInfo.length,
    }
  );

  functionInfo.forEach((func) => {
    // Split the function call into its components
    const components = func.split(".");

    // Get the package name from the first component
    const packageName = components[0];

    // Get the class name from the second component
    const className = components[1];

    // Get the method name from the last component
    const methodName = components[components.length - 1];

    // Check if the package name is already in the functionMetaData object
    if (!functionMetaData[packageName]) {
      // If not, add it with an empty object
      functionMetaData[packageName] = {};
    }

    // Check if the class name is already in the functionMetaData object
    if (!functionMetaData[packageName][className]) {
      // If not, add it with an empty array
      functionMetaData[packageName][className] = [];
    }

    // Add the method name to the array
    functionMetaData[packageName][className].push(methodName);

    // Update the progress bar
    bar.tick();
  });

  // Write the function metadata to a JSON file
  fs.writeFileSync(
    "java_function_metadata.json",
    JSON.stringify(functionMetaData, null, 4)
  );
};

init();
