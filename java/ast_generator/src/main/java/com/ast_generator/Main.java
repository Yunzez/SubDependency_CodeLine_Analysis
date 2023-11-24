package com.ast_generator;

import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonReader;
import javax.json.JsonWriter;
import javax.json.stream.JsonGenerator;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.github.javaparser.ParseProblemException;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.ImportDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.serialization.JavaParserJsonSerializer;

public class Main {
    private static Map<String, String> dependencyMap;
    private static Path astPath;
    private static Map<String, String> libraryAstJsonMap;

    public static void main(String[] args) throws IOException {
        Scanner scanner = new Scanner(System.in);
        libraryAstJsonMap = new HashMap<>();
        // Delete existing ast.json file if it exists
        System.out.print("initializing");
        astPath = Paths.get("asts/main/ast.json");
        if (Files.exists(astPath)) {
            try {
                Files.delete(astPath);
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else {
            Files.createDirectories(astPath.getParent());
        }

        System.out.print("Please enter the path to the Java source file (hit enter for default): ");
        String rootDirectoryPath = scanner.nextLine().trim();

        if (rootDirectoryPath.isEmpty()) {
            rootDirectoryPath = "java/Encryption-test";
        }

        // Validate and process the directory
        Path rootPath = Paths.get(rootDirectoryPath);

        // ! process directory (local java file)
        DirectoryProcessor processor = new DirectoryProcessor(rootDirectoryPath, astPath);
        processor.processDirectory();

        // Infer the path to pom.xml
        String inferredPomPath = rootPath.resolve("pom.xml").toString();
        System.out.println("Inferred path to pom.xml: " + inferredPomPath);

        // Check if the inferred path is correct
        System.out.print("Is this path correct? (yes/no): ");
        String response = scanner.nextLine();
        if ("no".equalsIgnoreCase(response)) {
            System.out.print("Please enter the correct path to the pom.xml: ");
            inferredPomPath = scanner.nextLine();
        }

        // ! process dependencies
        DependencyProcessor.processDependencies(inferredPomPath);

        scanner.close();
    }
    
    private static void appendAllASTsToJsonFile() throws IOException {
        JsonObjectBuilder jsonBuilder = Json.createObjectBuilder();

        if (Files.exists(astPath)) {
            String existingContent = Files.readString(astPath);
            JsonObject existingJson = Json.createReader(new StringReader(existingContent)).readObject();
            jsonBuilder = Json.createObjectBuilder(existingJson);
        }

        libraryAstJsonMap.forEach(jsonBuilder::add);

        try (JsonWriter jsonWriter = Json.createWriter(
                Files.newBufferedWriter(astPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE))) {
            jsonWriter.writeObject(jsonBuilder.build());
        }
    }

}
