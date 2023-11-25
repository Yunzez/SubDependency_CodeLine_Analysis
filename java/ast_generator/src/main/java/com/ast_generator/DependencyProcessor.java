package com.ast_generator;

import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.stream.JsonGenerator;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.github.javaparser.ParseProblemException;
import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.serialization.JavaParserJsonSerializer;

public class DependencyProcessor {
    private static String pomPath;
    private static Map<String, Dependency> dependencyMap;
    private static ImportManager importManager;
    private static Path outputDir;

    public DependencyProcessor() {
    }

    public static void processDependencies(String pomPath, ImportManager importManager) {
        DependencyProcessor.importManager = importManager;
        DependencyProcessor.pomPath = pomPath;
        System.out.println("Processing pom.xml: " + pomPath);
        dependencyMap = parsePomForDependencies(pomPath);

        System.out
                .println("---------------------------- generate AST for all dependencies ----------------------------");
        generateASTForAllDependencies();

        System.out.println(
                "---------------------------- Done generating AST for all dependencies ----------------------------");
    }

    public static Map<String, Dependency> parsePomForDependencies(String pomFilePath) {
        Map<String, Dependency> dependencyMap = new HashMap<>();
        try {
            DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
            Document doc = dBuilder.parse(new File(pomFilePath));
            doc.getDocumentElement().normalize();

            NodeList dependenciesList = doc.getElementsByTagName("dependency");
            System.out.println("Number of dependencies: " + dependenciesList.getLength());
            System.out.println("----------------------------");
            for (int i = 0; i < dependenciesList.getLength(); i++) {
                Node dependencyNode = dependenciesList.item(i);
                // System.out.println("\nCurrent Element :" + dependencyNode.getNodeName());
                if (dependencyNode.getNodeType() == Node.ELEMENT_NODE) {
                    Element dependencyElement = (Element) dependencyNode;

                    String groupId = dependencyElement.getElementsByTagName("groupId").item(0).getTextContent();
                    String artifactId = dependencyElement.getElementsByTagName("artifactId").item(0).getTextContent();
                    String version = dependencyElement.getElementsByTagName("version").item(0).getTextContent();

                    String mavenPath = System.getProperty("user.home") + "/.m2/repository/"
                            + groupId.replace('.', '/') + "/" + artifactId + "/" + version
                            + "/" + artifactId + "-" + version + ".jar";

                    Dependency dependency = new Dependency(groupId, artifactId, version, mavenPath);
                    dependencyMap.put(artifactId, dependency);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return dependencyMap;
    }

    // Generate AST for all dependencies
    public static void generateASTForAllDependencies() {
        dependencyMap.forEach((artifactId, dependecy) -> {
            String mavenPath = dependecy.getJarPath();
            if (Files.exists(Paths.get(mavenPath)) && mavenPath.endsWith(".jar")) {
                System.out.println("Found jar at: " + mavenPath + " for artifact: " + artifactId);
                try {
                    Path decompiledDir = decompileJarWithJdCli(mavenPath);
                    // System.out.println("extracting from: " + decompiledDir);
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
        DependencyProcessor.outputDir = Paths.get(System.getProperty("user.dir"), outputDirName);
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

    private static Set<String> convertImportsToPackageNames(Set<String> imports) {
        // Convert import statements to package names
        // e.g., org.apache.commons.crypto.cipher.CryptoCipher ->
        // org.apache.commons.crypto.cipher
        return imports.stream()
                .map(imp -> imp.substring(0, imp.lastIndexOf('.')))
                .collect(Collectors.toSet());
    }

    private static boolean isRelevantFile(Path filePath, Set<String> thirdPartyPackages) {
        String pathString = filePath.toString();

        // Calculate startingIndex based on the output directory path
        String outputDirPath = DependencyProcessor.outputDir.toString();
        int startingIndex = outputDirPath.endsWith("/") ? outputDirPath.length() : outputDirPath.length() + 1;

        // Extract the package-like structure from the path
        String packageName = pathString.substring(startingIndex).replace('/', '.');

        // Remove the file name and extension to get the package name
        if (packageName.contains(".")) {
            packageName = packageName.substring(0, packageName.lastIndexOf('.'));
            packageName = packageName.substring(0, packageName.lastIndexOf('.'));
        }
        // if(thirdPartyPackages.stream().anyMatch(importStr ->
        // pathString.contains(importStr.replace('.', '/')))) {
        // System.out.println("packageName matched: " + packageName + '\n' +
        // "pathString: " + filePath);
        // }
        // Check if this package is in the set of third-party packages
        return thirdPartyPackages.stream().anyMatch(importStr -> pathString.contains(importStr.replace('.', '/')));

    }

    private static void extractJavaFilesFromDir(Path dir) throws IOException {

        // ! ! uncomment his to get verbose ast (ast of the all related files)
        // !! eg. import org.jasypt.util.text.BasicTextEncryptor; we will get org.jasypt.util.text instead
        // Set<String> thirdPartyPackages =
        // convertImportsToPackageNames(importManager.getThirdPartyImports());
        
        Set<String> thirdPartyPackages = importManager.getThirdPartyImports();
        System.out.println("checking third party packages: " + thirdPartyPackages.toString());

        Files.walk(dir)
                .filter(path -> path.toString().endsWith(".java"))
                .filter(path -> isRelevantFile(path, thirdPartyPackages)) // Filter out irrelevant files
                .forEach(path -> {
                    try {
                        CompilationUnit cu = StaticJavaParser.parse(path);
                        // System.out.println("Parsed successfully " + path);

                        StringWriter stringWriter = new StringWriter();
                        try (JsonGenerator jsonGenerator = Json.createGenerator(stringWriter)) {
                            JavaParserJsonSerializer serializer = new JavaParserJsonSerializer();
                            serializer.serialize(cu, jsonGenerator);
                        }

                        String astJson = stringWriter.toString();

                        createJsonForCurrentFile(path.getFileName().toString(), astJson);
                        // libraryAstJsonMap.put(path.getFileName().toString(), astJson);

                    } catch (ParseProblemException | IOException e) {
                        System.err.println("Failed to parse (skipping): " + path);
                    }
                });
        // appendAllASTsToJsonFile();
        // Cleanup: delete the temporary directory and extracted files
        try (Stream<Path> walk = Files.walk(dir).sorted(Comparator.reverseOrder())) {
            walk.forEach(path -> {
                try {
                    Files.delete(path);
                    // System.out.println("Deleted: " + path);
                } catch (IOException e) {
                    System.err.println("Failed to delete: " + path + "; " + e.getMessage());
                }
            });
        } catch (IOException e) {
            System.err.println("Error walking through directory: " + e.getMessage());
        }
    }

    public static void createJsonForCurrentFile(String fileName, String astJson) {
        // System.out.println("Current working directory: " +
        // System.getProperty("user.dir"));

        try {
            // Ensure directory exists
            Path dirPath = Path.of("asts");
            if (!Files.exists(dirPath)) {
                Files.createDirectories(dirPath);
            }

            // Construct the file path
            Path filePath = dirPath.resolve(fileName.substring(0, fileName.length() - 5) + ".json");
            if (!Files.exists(filePath)) {
                Files.createDirectories(dirPath);
            } else {
                Files.delete(filePath);
                // recreate the files
                Files.createDirectories(dirPath);
            }
            // Parse the AST JSON data
            JsonReader jsonReader = Json.createReader(new StringReader(astJson));
            JsonObject astJsonObject = jsonReader.readObject();
            jsonReader.close();

            // Create a new JSON object with fileName as the key
            JsonObject wrappedJson = Json.createObjectBuilder()
                    .add(fileName, astJsonObject)
                    .build();

            // Convert the new JSON object to string
            String wrappedJsonString = wrappedJson.toString();

            // Write the new JSON data to the file
            Files.writeString(filePath, wrappedJsonString, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
        } catch (IOException e) {
            System.err.println("Error handling file: " + fileName + " - " + e.getMessage());
            e.printStackTrace(); // Print the full stack trace for more detailed error information
        }
    }

}
