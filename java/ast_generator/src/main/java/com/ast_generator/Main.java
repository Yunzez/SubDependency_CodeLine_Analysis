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
        astPath = Paths.get("java/ast_generator/ast.json");
        if (Files.exists(astPath)) {
            try {
                Files.delete(astPath);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        System.out.print("Please enter the path to the Java source file (hit enter for default): ");
        String rootDirectoryPath = scanner.nextLine().trim();

        if (rootDirectoryPath.isEmpty()) {
            rootDirectoryPath = "java/Encryption-test";
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

        // Filter the dependency map based on these imports
        System.out.println("Dependency map: " + dependencyMap.toString());

        // generateASTForAllDependencies();
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

        try {
            CompilationUnit cu = StaticJavaParser.parse(path);
            StringWriter stringWriter = new StringWriter();
            try (JsonGenerator jsonGenerator = Json.createGenerator(stringWriter)) {
                JavaParserJsonSerializer serializer = new JavaParserJsonSerializer();
                serializer.serialize(cu, jsonGenerator);
            }

            String astJson = stringWriter.toString();
            appendLocalASTToJsonFile(path.toString(), astJson);
        } catch (IOException e) {
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

    // Generate AST for all dependencies
    public static void generateASTForAllDependencies() {
        dependencyMap.forEach((artifactId, mavenPath) -> {
            if (Files.exists(Paths.get(mavenPath)) && mavenPath.endsWith(".jar")) {
                System.out.println("Found jar at: " + mavenPath + " for artifact: " + artifactId);
                try {
                    Path decompiledDir = decompileJarWithJdCli(mavenPath);
                    System.out.println("extracting from: " + decompiledDir);
                    extractJavaFilesFromDir(decompiledDir);
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (InterruptedException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            } else {
                System.out.println("Skipping non-jar path: " + mavenPath);
            }
        });
    }

    private static Path decompileJarWithJdCli(String jarPath) throws IOException, InterruptedException {
        String outputDirName = "jd-cli-output";
        Path outputDir = Paths.get(System.getProperty("user.dir"), outputDirName);
        if (!Files.exists(outputDir)) {
            Files.createDirectories(outputDir);
        }
        String command = "java -jar java/ast_generator/jd-cli.jar --outputDir " + outputDir + " " + jarPath;
        Process process = Runtime.getRuntime().exec(command);
        int exitVal = process.waitFor(); // Wait for the process to complete
        if (exitVal != 0) {
            throw new IOException("Decompilation failed with exit code " + exitVal);
        }
        return outputDir;
    }

    private static void extractJavaFilesFromDir(Path dir) throws IOException {
        Files.walk(dir)
                .filter(path -> path.toString().endsWith(".java"))
                .forEach(path -> {
                    try {
                        CompilationUnit cu = StaticJavaParser.parse(path);
                        System.out.println("Parsed successfully " + path);

                        StringWriter stringWriter = new StringWriter();
                        try (JsonGenerator jsonGenerator = Json.createGenerator(stringWriter)) {
                            JavaParserJsonSerializer serializer = new JavaParserJsonSerializer();
                            serializer.serialize(cu, jsonGenerator);
                        }

                        String astJson = stringWriter.toString();
                        libraryAstJsonMap.put(path.getFileName().toString(), astJson);

                    } catch (ParseProblemException | IOException e) {
                         System.err.println("Failed to parse (skipping): " + path);
                    }
                });
        appendAllASTsToJsonFile();
        // Cleanup: delete the temporary directory and extracted files
        Files.walk(dir)
                .sorted(Comparator.reverseOrder()) // delete contents before directory
                .forEach(path -> {
                    // Files.delete(path);
                    System.out.println("Deleting: " + path);
                });

    }

    // ! only includes function declarations
    // private static void extractJavaFilesFromDir(Path dir) throws IOException {
    //     Files.walk(dir)
    //             .filter(path -> path.toString().endsWith(".java"))
    //             .forEach(path -> {
    //                 try {
    //                     CompilationUnit cu = StaticJavaParser.parse(path);
    //                     System.out.println("Parsed successfully " + path);
    //                     List<MethodDeclaration> methodDeclarations = cu.findAll(MethodDeclaration.class);

    //                     // Serialize only method declarations
    //                     StringWriter stringWriter = new StringWriter();
    //                     for (MethodDeclaration method : methodDeclarations) {
    //                         try (JsonGenerator jsonGenerator = Json.createGenerator(stringWriter)) {
    //                             JavaParserJsonSerializer serializer = new JavaParserJsonSerializer();
    //                             serializer.serialize(method, jsonGenerator);
    //                         }
    //                         // Add a separator if required, for example, a comma for JSON array
    //                     }

    //                     String methodsJson = stringWriter.toString();
    //                     libraryAstJsonMap.put(path.getFileName().toString(), methodsJson);

    //                 } catch (ParseProblemException | IOException e) {
    //                     System.err.println("Failed to parse (skipping): " + path);
    //                 }
    //             });

    //     appendAllASTsToJsonFile();
    //     // Cleanup...
    // }

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
