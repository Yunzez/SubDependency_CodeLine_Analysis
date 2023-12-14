## Sub-Dependency CodeLine Analysis Project

---

This is an quick demo for CodeLine analysis that supposes to reveal lines of code of functions in dependencies for a SBOM research

Currently only in python / Rust

- To run the python demo:

```python
pip3 install -r requirements.txt
python3 ./python/test.py ./python/img_to_pdf.py
```

---

To run the Rust demo:

1. **Install Rust and Cargo**: If you haven't installed Rust and Cargo (Rust's package manager), you can install them from [here](https://rust-lang.org/tools/install).

2. **Navigate to the Rust project directory**:

   ```bash
   cd ./rust/demo_project_directory/
   ```

3. **Build the Project**:

   ```bash
   cargo build
   ```

4. **Run the Project**:

   ```bash
   cargo run
   ```

5. **Now we will have a rust AST, we can run our ast_analyzer**: 

   ```bash
    npm install
    ts-node analyzer.ts
   ```

6. **You will get a prompt ask: "  please input your rust ast file path: › "**
 ```bash
 ? please input your rust ast file path: › ../ast_generator/ast.json

 # or you can leave it empty , that will lead to the default demo
 ```


--- 
To run Java Analysis Demo:

**This section covers the process for analyzing Java projects to reveal lines of code in functions within dependencies.**

### Prerequisites

- Ensure Java and Maven are installed on your system.
- Node.js and TypeScript should also be installed for running the TypeScript scripts.

### Steps to Run Java Files

1. **Use Java AST Generator**:
    
    - Navigate to the `java/ast_generator` directory.
    - Run the AST generator with the path to your Java project. This will infer `pom.xml` and generate the corresponding AST.
        
        ```bash
        cd java/ast_generator java AstGenerator <path-to-your-java-project>
        ```
        
2. **Run AST Analyzer in TypeScript**:
    
    - Navigate to the `ast_analyzer` directory.
    - Run the analyzer script using TypeScript.
        
        ```bash
        cd ast_analyzer ts-node analyzer.ts
        ```
        
    - This process will generate two files: `java_ast_local_file_analysis.json` and `java_ast_third_party_analysis.json`.
3. **Optionally Run AST Visualizer**:
    
    - To visualize the analysis, navigate to the `ast_visualizer` directory.
    - Start the local server to view the visualization.
        
       ```bash
       cd ast_visualizer npm install npm run dev
       ```
        
4. **Generate Complete SBOM**:
    
    - For generating a complete SBOM, go to the `SBOM_generator` directory.
    - Run the SBOM generator script.
        

        ```bash
         cd SBOM_generator ts-node index.ts
        ```
        
    - Follow the prompts to specify the path to your Java project.

### Additional Information

- Make sure to replace `<path-to-your-java-project>` with the actual path to your Java project in the AST generator step.
- The SBOM generator script will prompt you for necessary inputs during execution.
