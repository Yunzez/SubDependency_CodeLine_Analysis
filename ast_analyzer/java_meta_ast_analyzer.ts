import * as fs from "fs";
import { analyzeJava } from "./java_analyzer";
import path from "path";
// * this part is for gathering meta data from third party ASTs

export const collectMetaInfo = async (astFilePath: string) => {
  if (!fs.existsSync(astFilePath)) {
    console.log(`AST file not found: ${astFilePath}`);
    return;
  }

  const metaAstOutputPath = "./subAst/output";
  const functionsRequiredInfo = gatherFunctionsCall(astFilePath);
  await processMetaAstData(metaAstOutputPath);

  console.log("Merging analysis files");
  mergeAnalysis("./java_ast_third_party_analysis.json", "./metaAst.json");
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
      // ! generate same output analysis file as the third party analysis with name of metaAst.json
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

const mergeAnalysis = (basePath: string, addsonPath: string) => {
  if (!fs.statSync(basePath).isFile() || !fs.statSync(addsonPath).isFile()) {
    console.log("File not found");
    return null;
  }

  const addonContent = JSON.parse(fs.readFileSync(addsonPath, "utf8"));
  const baseContent = JSON.parse(fs.readFileSync(basePath, "utf8"));
  const addonAnalysisMap = new Map<string, AnalysisResult>();

  for (const [functionName, functionData] of Object.entries(addonContent)) {
    addonAnalysisMap.set(functionName, functionData as AnalysisResult);
  }

  console.log(
    "finish creating addon analysis reference,  size: ",
    addonAnalysisMap.size
  );

  for (const [key, value] of Object.entries(baseContent)) {
    const baseFunctionData = value as AnalysisResult;
    for (const exterFuncName in baseFunctionData.external_functions) {
      if (addonAnalysisMap.has(exterFuncName)) {
        console.log("found match: ", exterFuncName);
        const addonFunctionData = addonAnalysisMap.get(exterFuncName);
        baseFunctionData.external_functions[exterFuncName] = {
          call_line: baseFunctionData.external_functions[exterFuncName],
          exter_func_info: addonFunctionData?.self_information ?? "Null",
        };
      }
    }
  }

  // Optionally, write the merged analysis back to a file
  fs.writeFileSync(basePath, JSON.stringify(baseContent, null, 2));
};

type AnalysisResult = {
  external_functions: Record<string, any>;
  internal_functions: Record<string, any>;
  self_information: Record<string, any>;
};
