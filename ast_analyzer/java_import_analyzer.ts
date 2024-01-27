import { exec } from "child_process";
import * as path from "path";
import * as fs from "fs";
import * as os from "os";

export class ImportAnalyzer {

relevantFilePaths: string[] = [];
constructor(relevantFilePaths: string[]) {
    this.relevantFilePaths = relevantFilePaths;
}

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
    console.log(`Analyzing JAR file: ${groupId.replace(/\./g, "/") + artifactId,
        version,
        artifactId + "-" + version}`);

    if (fs.existsSync(jarPath)) {
        console.log(`target: ${groupId.replace(/\./g, "/") + artifactId, version, artifactId + "-" + version}`)
      const outputDir = `./decompiled/${astFileName}`;
      await this.decompileJarWithJdCli(jarPath, outputDir);
      await this.filterAndProcessDecompiledFiles(outputDir, importStatements);

      this.deleteEmptyDirectories(outputDir);
      // Further processing...
    } else {
      console.log(`JAR file not found: ${jarPath}`);
    }
  }

  async filterAndProcessDecompiledFiles(
    outputDir: string,
    importStatements: string[],
  ) {
    const files = this.getAllFiles(outputDir);
    for (const filePath of files) {
      const relativePath = this.convertFilePathToPackagePath(
        filePath,
        outputDir
      );

      const isRelevant = importStatements.some((importStmt) =>
        relativePath.includes(importStmt)
      );
      if (!isRelevant) {
        // File does not match any import statement, delete it
        // console.log(`Deleting irrelevant file: ${filePath}`);
        fs.unlinkSync(filePath);
      } else {
        this.relevantFilePaths.push(filePath);
        // File matches an import statement, process it further
        console.log(`Processing relevant file: ${filePath}`);
        // Call your AST generation or other processing methods here
      }
    }

    // await this.runDirectoryProcessor(outputDir, "../ast_analyzer/sub_ast");
  }

  private runDirectoryProcessor(
    decompiledDir: string,
    astOutputDir: string
  ): Promise<void> {
    return new Promise((resolve, reject) => {
        const javaDecompilationDir = "../ast_analyzer/decompiled"
      const command = `/usr/bin/env /Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home/bin/java @/var/folders/9w/qz54k17x6zg0n9c2zm3kccz40000gn/T/cp_d3xggjeqc1p2bqsmyr7i4eqxu.argfile com.ast_generator.DirectoryProcessor ${javaDecompilationDir} ${astOutputDir}`;
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

  private deleteEmptyDirectories(directory: string) {
    // Get all files and directories in the current directory
    const entries = fs.readdirSync(directory);

    entries.forEach((entry) => {
        const fullPath = path.join(directory, entry);
        const stat = fs.statSync(fullPath);

        if (stat.isDirectory()) {
            this.deleteEmptyDirectories(fullPath);
        }
    });

    // Re-check if the directory is empty
    try {
        if (fs.readdirSync(directory).length === 0) {
            console.log(`Deleting empty directory: ${directory}`);
            fs.rmdirSync(directory);
        }
    } catch (error) {
        console.error(`Error deleting directory ${directory}`);
    }
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
