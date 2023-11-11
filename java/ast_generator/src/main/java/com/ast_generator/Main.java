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
import java.util.Map;
import java.util.Scanner;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
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
import com.github.javaparser.serialization.JavaParserJsonSerializer;

public class Main {
    private static Map<String, String> dependencyMap;

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        // Delete existing ast.json file if it exists
         System.out.print("initializing");
        Path astFilePath = Paths.get("java/ast_generator/ast.json");
        if (Files.exists(astFilePath)) {
            try {
                Files.delete(astFilePath);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        System.out.print("Please enter the path to the Java source file (hit enter for default): ");
        String rootDirectoryPath = scanner.nextLine().trim();

        if (rootDirectoryPath.isEmpty()) {
            rootDirectoryPath = "java/Calculator-master";
        }

        // Validate and process the directory
        Path rootPath = Paths.get(rootDirectoryPath);
        if (Files.isDirectory(rootPath)) {
            try {
                System.out.println("Processing directory: " + rootPath);
                processDirectory(rootPath);
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else {
            System.out.println("Invalid directory path.");
        }

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

        dependencyMap = parsePomForDependencies(inferredPomPath);

        generateAST(rootDirectoryPath);
        generateASTForAllDependencies();
        scanner.close();
    }

    private static void processDirectory(Path directory) throws IOException {
        Files.walkFileTree(directory, new SimpleFileVisitor<Path>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                if (file.toString().endsWith(".java")) {
                    generateAST(file.toString());
                }
                return FileVisitResult.CONTINUE;
            }
        });
    }

    private static void generateAST(String sourceFilePath) {
        // Configure parser
        ParserConfiguration config = new ParserConfiguration();
        StaticJavaParser.setConfiguration(config);
        Path path = Paths.get(sourceFilePath);

        if (!Files.exists(path)) {
            System.out.println("File does not exist: " + sourceFilePath);
            return;
        }

        try {
            CompilationUnit cu = StaticJavaParser.parse(path);
            StringWriter stringWriter = new StringWriter();
            try (JsonGenerator jsonGenerator = Json.createGenerator(stringWriter)) {
                JavaParserJsonSerializer serializer = new JavaParserJsonSerializer();
                serializer.serialize(cu, jsonGenerator);
            }

            String astJson = stringWriter.toString();
            Path astFilePath = Paths.get("java/ast_generator/ast.json");
            appendASTToJsonFile(astFilePath, path.toString(), astJson);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void appendASTToJsonFile(Path astFilePath, String sourceFilePath, String astJson)
            throws IOException {
        JsonObjectBuilder jsonBuilder = Json.createObjectBuilder();

        if (Files.exists(astFilePath)) {
            // Parse existing JSON and add new AST
            String existingContent = Files.readString(astFilePath);
            JsonObject existingJson = Json.createReader(new StringReader(existingContent)).readObject();
            jsonBuilder = Json.createObjectBuilder(existingJson);
        }

        // Add new AST
        JsonObject newAst = Json.createReader(new StringReader(astJson)).readObject();
        jsonBuilder.add(sourceFilePath, newAst);

        // Write back to file
        try (JsonWriter jsonWriter = Json.createWriter(
                Files.newBufferedWriter(astFilePath, StandardOpenOption.CREATE, StandardOpenOption.WRITE))) {
            jsonWriter.writeObject(jsonBuilder.build());
        }
    }

    public static void generateASTForAllDependencies() {

        dependencyMap.forEach((artifactId, mavenPath) -> {
            if (Files.exists(Paths.get(mavenPath)) && mavenPath.endsWith(".jar")) {
                System.out.println("Found jar at: " + mavenPath + " for artifact: " + artifactId);
                try {
                    // Extract Java files from the jar
                    extractJavaFilesFromJar(mavenPath);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            } else {
                System.out.println("Skipping non-jar path: " + mavenPath);
            }
        });
    }

    private static void extractJavaFilesFromJar(String jarPath) throws IOException {
        Path tempDir = Files.createTempDirectory("jar-extract");
        System.out.println("parsing: " + jarPath + " " + tempDir);
        try (ZipInputStream zipInputStream = new ZipInputStream(Files.newInputStream(Paths.get(jarPath)))) {
            ZipEntry entry;

            while ((entry = zipInputStream.getNextEntry()) != null) {
                System.out.println("parsing entry:" + entry.toString() + " " + tempDir);
                if (entry.getName().endsWith(".java")) {
                    Path outputFile = tempDir.resolve(entry.getName());
                    Files.createDirectories(outputFile.getParent()); // ensure directory structure
                    Files.copy(zipInputStream, outputFile, StandardCopyOption.REPLACE_EXISTING);
                    // Now parse the Java file using JavaParser
                    try {
                        CompilationUnit cu = StaticJavaParser.parse(outputFile);
                        System.out.println("Parsed successfully " + outputFile);
                        // TODO: Do whatever you want with the parsed CompilationUnit
                    } catch (ParseProblemException e) {
                        System.err.println("Failed to parse: " + outputFile);
                        e.printStackTrace();
                    }
                }
            }
        } finally {
            // Cleanup: delete the temporary directory and extracted files
            Files.walk(tempDir)
                    .sorted(Comparator.reverseOrder()) // delete contents before directory
                    .forEach(path -> {
                        try {
                            Files.delete(path);
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    });
        }
    }

    private static Map<String, String> parsePomForDependencies(String pomFilePath) {
        Map<String, String> dependencyMap = new HashMap<>();
        try {
            DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
            Document doc = dBuilder.parse(new File(pomFilePath));
            doc.getDocumentElement().normalize();

            NodeList dependenciesList = doc.getElementsByTagName("dependency");

            for (int i = 0; i < dependenciesList.getLength(); i++) {
                Node dependencyNode = dependenciesList.item(i);
                if (dependencyNode.getNodeType() == Node.ELEMENT_NODE) {
                    Element dependencyElement = (Element) dependencyNode;

                    String groupId = dependencyElement.getElementsByTagName("groupId").item(0).getTextContent();
                    String artifactId = dependencyElement.getElementsByTagName("artifactId").item(0).getTextContent();
                    String version = dependencyElement.getElementsByTagName("version").item(0).getTextContent();

                    String mavenPath = System.getProperty("user.home") + "/.m2/repository/"
                            + groupId.replace('.', '/') + "/" + artifactId + "/" + version
                            + "/" + artifactId + "-" + version + ".jar";

                    dependencyMap.put(artifactId, mavenPath);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return dependencyMap;
    }
}
