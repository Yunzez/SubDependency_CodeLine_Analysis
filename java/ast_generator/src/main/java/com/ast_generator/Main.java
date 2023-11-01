package com.ast_generator;

import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.serialization.JavaParserJsonSerializer;

import javax.json.Json;
import javax.json.stream.JsonGenerator;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.file.FileVisitOption;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.EnumSet;
import java.util.Scanner;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

public class Main {
    public static void main(String[] args) {
        System.out.println("Hello world!");
        // Ensure a source file is provided as an argument
        Scanner scanner = new Scanner(System.in);
        System.out.print("Please enter the path to the Java source file (hit enter for default): ");
        String sourceFilePath = scanner.nextLine();
        if (sourceFilePath == null || sourceFilePath.isEmpty()) {
            sourceFilePath = "java/ast_generator/src/main/java/com/ast_generator/Main.java";
        }
        generateAST(sourceFilePath);
        scanner.close();
    }

    private static void generateAST(String sourceDirectoryPath) {

        ParserConfiguration config = new ParserConfiguration();
        StaticJavaParser.setConfiguration(config);

        Path path = Paths.get(sourceDirectoryPath);
        if (!Files.exists(path)) {
            System.out.println("File does not exist: " + sourceDirectoryPath);
            return;
        }
        try {
            Path startDir = Paths.get(sourceDirectoryPath);
            StringBuilder jsonOutput = new StringBuilder(); // Create a StringBuilder to accumulate JSON outputs

            Files.walkFileTree(startDir, EnumSet.noneOf(FileVisitOption.class), Integer.MAX_VALUE,
                    new SimpleFileVisitor<Path>() {
                        @Override
                        public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                            if (file.toString().endsWith(".java")) {
                                CompilationUnit cu = StaticJavaParser.parse(file);

                                StringWriter stringWriter = new StringWriter();
                                JsonGenerator jsonGenerator = Json.createGenerator(stringWriter);
                                JavaParserJsonSerializer serializer = new JavaParserJsonSerializer();
                                serializer.serialize(cu, jsonGenerator);
                                jsonGenerator.close();

                                // System.out.println("File: " + file);
                                // System.out.println(stringWriter.toString());
                                jsonOutput.append(stringWriter.toString()).append("\n"); // Append the JSON output for
                                                                                         // this file to the
                                                                                         // StringBuilder
                            }
                            return FileVisitResult.CONTINUE;
                        }

                        @Override
                        public FileVisitResult visitFileFailed(Path file, IOException exc) throws IOException {
                            return FileVisitResult.CONTINUE;
                        }
                    });

            Path outputFile = Paths.get("java/ast_generator/ast.json");
            Files.write(outputFile, jsonOutput.toString().getBytes(StandardCharsets.UTF_8));
            System.out.println("JSON output saved to: " + outputFile.toAbsolutePath());

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

// java/Encryption-test/src/main/java/com/encryption/App.java