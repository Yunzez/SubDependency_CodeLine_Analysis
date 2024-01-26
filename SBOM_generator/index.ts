import { exec } from "child_process";
import { promisify } from "util";
import fs from "fs";
import path from "path";
import readline from "readline";
import { CustomData, MethodCallInfo } from "./Interfaces";

function askQuestion(query: string): Promise<string> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return new Promise((resolve) =>
    rl.question(query, (ans) => {
      rl.close();
      resolve(ans);
    })
  );
}

const execAsync = promisify(exec);

async function generateJavaStandardSBOM(projectPath: string): Promise<void> {
  try {
    // Command to generate SBOM using Maven and CycloneDX Maven plugin
    const command = `mvn -f ${projectPath}/pom.xml cyclonedx:makeBom -DoutputFormat=JSON`;

    const { stdout, stderr } = await execAsync(command);
    console.log("Command Output:", stdout);
    console.error(stderr ? "Command Error:" + stderr : "");
    console.log(
      "Standard SBOM generated for Java project at: ",
      projectPath + "/target/bom.xml"
    );
  } catch (error) {
    console.error("Error generating Java standard SBOM:", error);
  }
}

async function readCustomData(): Promise<CustomData> {
  let filePath = await askQuestion(
    "Please enter the path to the local AST summary file (default: ../ast_analyzer/java_ast_local_file_analysis.json): "
  );

  if (!filePath) {
    // throw new Error('File path not provided.');
    filePath = "../ast_analyzer/java_ast_local_file_analysis.json";
  }

  try {
    const data = await fs.promises.readFile(filePath, "utf-8");
    const parsedData = JSON.parse(data) as CustomData;
    return parsedData;
  } catch (error) {
    console.error("Error reading custom data:", error);
    throw error; // or handle it as needed
  }
}

async function mergeSBOMWithCustomData(
  sbomPath: string,
  customData: CustomData
): Promise<void> {
  try {
    const sbomContent = await fs.promises.readFile(sbomPath, "utf-8");
    let sbom = JSON.parse(sbomContent);

    Object.values(customData)[0].forEach((functionInfo) => {
      sbom.components.forEach((component: any) => {
        if (functionInfo["thirdPartyInfo"] !== undefined) {
          const externalClassInfo = functionInfo["thirdPartyInfo"];
          let className = externalClassInfo["self"].className;
          // Combine group and name for comparison
          
          let combinedName = `${component.group}.${component.name}`;
          console.log("Component:", combinedName.replace(/-/g, '.'), "Class:", className.replace(/Optional\[(.*?)\]/, '$1'));
          combinedName = combinedName.replace(/-/g, '.')
          className = className.replace(/Optional\[(.*?)\]/, '$1')
          
          if (className.includes(combinedName)) {
            component.extensions = component.extensions || [];
            component.extensions.push({
              name: "Dependency method call information",
              data: functionInfo,
            });
          }
        }
      });
    });

    await fs.promises.writeFile(sbomPath, JSON.stringify(sbom, null, 4));
    console.log("SBOM merged with custom data at:", sbomPath);
  } catch (error) {
    console.error("Error merging SBOM with custom data:", error);
  }
}

async function main() {
  let projectPath = await askQuestion(
    "Please enter the path to the Java project (Default: ../java/Encryption-test): "
  );
  if (!projectPath) {
    projectPath = "../java/Encryption-test";
    console.error("No path provided, using default.");
  }

  const sbomPath = projectPath + "/target/bom.json";

  await generateJavaStandardSBOM(projectPath);
  console.log("SBOM generated at:", sbomPath);
  const customData = await readCustomData();
  await mergeSBOMWithCustomData(sbomPath, customData);
}

main().catch(console.error);
