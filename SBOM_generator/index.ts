import { exec } from 'child_process';
import { promisify } from 'util';
import fs from 'fs';
import path from 'path';
import readline from 'readline';

function askQuestion(query: string): Promise<string> {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout,
    });

    return new Promise(resolve => rl.question(query, ans => {
        rl.close();
        resolve(ans);
    }));
}

const execAsync = promisify(exec);

async function generateJavaStandardSBOM(projectPath: string): Promise<void> {
    try {
        // Command to generate SBOM using Maven and CycloneDX Maven plugin
        const command = `mvn -f ${projectPath}/pom.xml cyclonedx:makeBom -DoutputFormat=JSON`;

        const { stdout, stderr } = await execAsync(command);
        console.log('Command Output:', stdout);
        console.error(stderr  ? 'Command Error:' + stderr : '');
        console.log('Standard SBOM generated for Java project at: ', projectPath + '/target/bom.xml');

    } catch (error) {
        console.error('Error generating Java standard SBOM:', error);
    }
}

interface CustomData {
    // Define the structure of your custom data
}

async function readCustomData(filePath: string): Promise<CustomData[]> {
    const data = await fs.promises.readFile(filePath, 'utf-8');
    return JSON.parse(data) as CustomData[];
}


async function mergeSBOMWithCustomData(sbomPath: string, customData: CustomData[]): Promise<void> {
    const sbomContent = await fs.promises.readFile(sbomPath, 'utf-8');
    let sbom = JSON.parse(sbomContent);

    sbom['customExtensions'] = {'functionCallDetails': customData};

    await fs.promises.writeFile(sbomPath, JSON.stringify(sbom, null, 4));
    console.log('SBOM merged with custom data at:', sbomPath);
}


async function main() {
    let projectPath = await askQuestion('Please enter the path to the Java project (Default: ../java/Encryption-test): ');
    if (!projectPath) {
        projectPath = "../java/Encryption-test"
        console.error('No path provided, using default.');
    }

    const sbomPath = projectPath + '/target/bom.json';
    const customDataPath = path.join(__dirname, 'custom_data.json');

    await generateJavaStandardSBOM(projectPath);
    console.log('SBOM generated at:', sbomPath);
    // const customData = await readCustomData(customDataPath);
    // await mergeSBOMWithCustomData(sbomPath, customData);
}

main().catch(console.error);
