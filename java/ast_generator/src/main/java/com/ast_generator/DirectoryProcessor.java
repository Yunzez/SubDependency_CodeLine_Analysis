package com.ast_generator;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Map;
import java.util.Set;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonWriter;
import javax.json.stream.JsonGenerator;

import com.github.javaparser.ParseProblemException;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.serialization.JavaParserJsonSerializer;

/*
 * this process local directory and generate AST for each java file
 */
public class DirectoryProcessor {
    private String directoryPath;
    private static Path astPath;
    private static Map<String, Dependency> dependencyMap;
    private static ImportManager importManager;

    public DirectoryProcessor() {
    }

    public DirectoryProcessor(String directoryPath, Path astPath) {
        this.directoryPath = directoryPath;
        DirectoryProcessor.astPath = astPath;
    }

    public DirectoryProcessor(String directoryPath, Path astPath, Map<String, Dependency> dependencyMap) {
        this.directoryPath = directoryPath;
        DirectoryProcessor.astPath = astPath;
        DirectoryProcessor.dependencyMap = dependencyMap;
    }

    // Main method for command-line execution

    // ! test statement:
    // cd /Users/yunzezhao/Code/SubDependency_CodeLine_Analysis ; /usr/bin/env
    // /Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home/bin/java
    // @/var/folders/9w/qz54k17x6zg0n9c2zm3kccz40000gn/T/cp_d3xggjeqc1p2bqsmyr7i4eqxu.argfile
    // com.ast_generator.DirectoryProcessor
    // /Users/yunzezhao/Code/SubDependency_CodeLine_Analysis/ast_analyzer/decompiled
    // /Users/yunzezhao/Code/SubDependency_CodeLine_Analysis/ast_analyzer/sub_ast
    public static void main(String[] args) {
        if (args.length == 2) {
            String sourcePath = Paths.get(args[0]).toString();
            Path outputPath = Paths.get(args[1]);
            DirectoryProcessor processor = new DirectoryProcessor(sourcePath, outputPath);
            processor.processDirectory();
        } else {
            System.out.println("Usage: java DirectoryProcessor <source directory> <AST output path>");
        }
    }

    public void processDirectory() {
        System.out.println("Processing directory: " + directoryPath);
        // Validate and process the directory
        Path rootPath = Paths.get(directoryPath);
        if (Files.isDirectory(rootPath)) {
            try {
                processDirectory(rootPath);
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else {
            System.out.println("Invalid directory path.");
        }
    }

    public void addImportMaganer(ImportManager manager) {
        DirectoryProcessor.importManager = manager;
    }

    private static void processDirectory(Path directory) throws IOException {
        Files.walkFileTree(directory, new SimpleFileVisitor<Path>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                if (file.toString().endsWith(".java")) {
                    System.out.println("Processing file: " + file);
                    generateAST(file.toString());
                }
                return FileVisitResult.CONTINUE;
            }
        });
    }

    private static void generateAST(String sourceFilePath) {
        // Configure parser
        System.out.println("Configuring parser... for file: " + sourceFilePath);
        ParserConfiguration config = new ParserConfiguration();
        StaticJavaParser.setConfiguration(config);
        Path path = Paths.get(sourceFilePath);

        try {
            CompilationUnit cu = StaticJavaParser.parse(path);

            if (dependencyMap == null) {
                System.out.println("dependencyMap is invalid, skipping dependency check");
            } else {
                FunctionSignatureExtractor extractor = new FunctionSignatureExtractor(
                        dependencyMap != null ? dependencyMap : null);
                extractor.extractThirdPartyImports(cu);
                Set<String> thirdPartyImports = extractor.getThirdPartyImports();

                // Store the imports in ImportManager
                if (importManager != null) {
                    importManager.addImports(thirdPartyImports);
                } else {
                    System.out.println("ImportManager is null");
                    System.out.println("---------------------------- third party imports ----------------------------");
                    for (String signature : thirdPartyImports) {
                        System.out.println(signature);
                    }
                }

            }

            StringWriter stringWriter = new StringWriter();
            try (JsonGenerator jsonGenerator = Json.createGenerator(stringWriter)) {
                JavaParserJsonSerializer serializer = new JavaParserJsonSerializer();
                serializer.serialize(cu, jsonGenerator);
            }

            String astJson = stringWriter.toString();
            appendLocalASTToJsonFile(path.toString(), astJson);
        } catch (IOException e) {
            System.err.println("Error parsing file: " + path);
            e.printStackTrace();
        } catch (ParseProblemException e) {
            System.err.println("Parse problem in file: " + sourceFilePath + ", Skipped");
            e.printStackTrace();
        }
    }

    private static void appendLocalASTToJsonFile(String sourceFilePath, String astJson)
            throws IOException {
        JsonObjectBuilder jsonBuilder = Json.createObjectBuilder();

        if (Files.exists(astPath)) {
            // Parse existing JSON and add new AST
            String existingContent = Files.readString(astPath);
            JsonObject existingJson = Json.createReader(new StringReader(existingContent)).readObject();
            jsonBuilder = Json.createObjectBuilder(existingJson);
        }

        // Add new AST
        JsonObject newAst = Json.createReader(new StringReader(astJson)).readObject();
        jsonBuilder.add(sourceFilePath, newAst);

        // Write back to file
        try (JsonWriter jsonWriter = Json.createWriter(
                Files.newBufferedWriter(astPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE))) {
            jsonWriter.writeObject(jsonBuilder.build());
        }
    }
}
