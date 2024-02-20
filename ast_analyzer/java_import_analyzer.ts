import { exec } from "child_process";
import * as path from "path";
import * as fs from "fs";
import * as os from "os";
import { analyzeJava } from "./java_analyzer";

export class ImportAnalyzer {
  constructor() {}

  getMavenJarPath(
    groupId: string,
    artifactId: string,
    version: string
  ): string {
    const homeDir = os.homedir();
    const groupPath = groupId.replace(/\./g, "/");
    return path.join(
      homeDir,
      ".m2",
      "repository",
      groupPath,
      artifactId,
      version,
      `${artifactId}-${version}.jar`
    );
  }

  decompileJarWithJdCli(jarPath: string, outputDir: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const command = `java -jar ../java/ast_generator/jd-cli.jar --outputDir ${outputDir} ${jarPath}`;
      exec(command, (error, stdout, stderr) => {
        if (error) {
          console.error(`Decompilation error: ${stderr}`);
          reject(error);
        } else {
          console.log(`Decompiled: ${stdout}`);
          resolve();
        }
      });
    });
  }

  // ! entrance
  async analyzeImport(
    groupId: string,
    artifactId: string,
    version: string,
    importStatements: string[],
    astFileName: string
  ) {
    const jarPath = this.getMavenJarPath(groupId, artifactId, version);
    console.log(
      `Analyzing JAR file: ${
        (groupId.replace(/\./g, "/") + artifactId,
        version,
        artifactId + "-" + version)
      }`
    );

    if (fs.existsSync(jarPath)) {
      console.log(
        `target: ${
          (groupId.replace(/\./g, "/") + artifactId,
          version,
          artifactId + "-" + version)
        }`
      );
      const outputDir = `./decompiled/${astFileName.split(".")[0]}`;
      await this.decompileJarWithJdCli(jarPath, outputDir);

      // info: this step filter out and delete the unneccessary files and directories
      await this.filterAndProcessDecompiledFiles(outputDir, importStatements);
      const directoryExists = await this.deleteEmptyDirectories(outputDir);

      if (directoryExists) {
        const astOutputDir = path.dirname(
          `./subAst/output/${astFileName.split(".")[0]}/sub_ast.json`
        );
        await this.runDirectoryProcessor(
          outputDir,
          `./subAst/output/${astFileName.split(".")[0]}/sub_ast.json`
        );

        console.log(`Directory ${outputDir} was processed`);
      } else {
        console.log(
          `Directory ${outputDir} was compeletely irrelavant and so deleted`
        );
      }

      // Further processing...
    } else {
      console.log(`JAR file not found: ${jarPath}`);
    }
  }

  private rerunAnalyzer(
    fileFormat: string,
    localAstDirectory: string,
    thirdPartyAstDirectory: string,
    localAnalysisOutputDir: string,
    thirdPartyAnalysisOutputDir: string
  ): Promise<void> {
    return new Promise((resolve, reject) => {
      // Check if the output directory exists, and create it if it doesn't
      // if (!fs.existsSync(localAnalysisOutputDir)) {
      //   fs.mkdirSync(localAnalysisOutputDir, { recursive: true });
      //   console.log(`Created directory: ${localAnalysisOutputDir}`);
      // }
      // if (!fs.existsSync(thirdPartyAnalysisOutputDir)) {
      //   fs.mkdirSync(thirdPartyAnalysisOutputDir, { recursive: true });
      //   console.log(`Created directory: ${thirdPartyAnalysisOutputDir}`);
      // }

      console.log("Local Source AST Code Directory: ", localAstDirectory);
      console.log(
        "Third Party Source AST Code Directory: ",
        thirdPartyAstDirectory
      );
      console.log("Local AST Output File: ", localAnalysisOutputDir);
      console.log("Third Party AST Output File: ", thirdPartyAnalysisOutputDir);

      const command = `ts-node analyzer.ts ${fileFormat} ${localAstDirectory} ${thirdPartyAstDirectory} ${localAnalysisOutputDir} ${thirdPartyAnalysisOutputDir}}`;
      exec(command, (error, stdout, stderr) => {
        if (error) {
          console.error(`DirectoryProcessor error: ${stderr}`);
          reject(error);
        } else {
          console.log(`DirectoryProcessor output: ${stdout}`);
          resolve();
        }
      });
    });
  }

  // * compare against the import statements to filter out the irrelevant files
  // * this function recursively deletes the irrelevant files and directory
  async filterAndProcessDecompiledFiles(
    outputDir: string,
    importStatements: string[]
  ) {
    const files = this.getAllFiles(outputDir);
    for (const filePath of files) {
      const relativePath = this.convertFilePathToPackagePath(
        filePath,
        outputDir
      );

      const isRelevant = importStatements.some((importStmt) => {
        if (relativePath.includes("META-INF")) {
          //   console.log("Skipping META-INF ( meta info ) file: " + relativePath);
          return false;
        }
        return relativePath.includes(importStmt);
      });

      if (!isRelevant) {
        fs.unlinkSync(filePath);
      }
    }
  }

  private runDirectoryProcessor(
    decompiledDir: string,
    astOutputFile: string
  ): Promise<void> {
    return new Promise((resolve, reject) => {
      const sourceCodeDir = path.resolve(decompiledDir);
      const astOutputFileJava = path.resolve(astOutputFile);
      const astOutputDir = path.dirname(astOutputFileJava); // Directory for the output file

      // Check if the output directory exists, and create it if it doesn't
      if (!fs.existsSync(astOutputDir)) {
        fs.mkdirSync(astOutputDir, { recursive: true });
        console.log(`Created directory: ${astOutputDir}`);
      }

      console.log("Source Code Directory: ", sourceCodeDir);
      console.log("AST Output File: ", astOutputFileJava);

      const command = `java -jar ../java/ast_generator/target/ast_generator-1.0.jar --process-directory ${sourceCodeDir} ${astOutputDir} --separate`;
      exec(command, (error, stdout, stderr) => {
        if (error) {
          console.error(`DirectoryProcessor error: ${stderr}`);
          reject(error);
        } else {
          console.log(`DirectoryProcessor output: ${stdout}`);
          resolve();
        }
      });
    });
  }

  // * recursively delete the empty directories, return false if the whole directory was deleted
  private async deleteEmptyDirectories(directory: string): Promise<boolean> {
    const entries = await fs.promises.readdir(directory);

    for (const entry of entries) {
      const fullPath = path.join(directory, entry);
      const stat = await fs.promises.stat(fullPath);

      if (stat.isDirectory()) {
        await this.deleteEmptyDirectories(fullPath);
      }
    }

    // Re-check if the directory is empty
    try {
      if ((await fs.promises.readdir(directory)).length === 0) {
        console.log(`Deleting empty directory: ${directory}`);
        await fs.promises.rmdir(directory);
        return false; // Directory was deleted
      }
    } catch (error) {
      console.error(`Error deleting directory ${directory}: ${error}`);
    }
    return true;
  }

  private getAllFiles(dirPath: string, arrayOfFiles: string[] = []): string[] {
    const files = fs.readdirSync(dirPath);

    for (const file of files) {
      const filePath = path.join(dirPath, file);
      if (fs.statSync(filePath).isDirectory()) {
        arrayOfFiles = this.getAllFiles(filePath, arrayOfFiles);
      } else {
        arrayOfFiles.push(filePath);
      }
    }

    return arrayOfFiles;
  }

  private convertFilePathToPackagePath(
    filePath: string,
    outputDir: string
  ): string {
    // Ensure the output directory ends with a path separator for correct substring operation
    const normalizedOutputDir = outputDir.endsWith(path.sep)
      ? outputDir
      : outputDir + path.sep;

    // Remove the output directory path from the file path
    let relativePath = filePath.startsWith(normalizedOutputDir)
      ? filePath.substring(normalizedOutputDir.length)
      : filePath;

    // Replace path separators with dots and remove the file extension
    relativePath = relativePath.replace(new RegExp(`\\${path.sep}`, "g"), ".");
    const lastDotIndex = relativePath.lastIndexOf(".");
    if (lastDotIndex !== -1) {
      relativePath = relativePath.substring(0, lastDotIndex);
    }

    return relativePath;
  }
}

export default ImportAnalyzer;
// Example usage
// analyzeImport("org.jasypt", "jasypt", "1.9.3");
