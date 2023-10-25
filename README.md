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