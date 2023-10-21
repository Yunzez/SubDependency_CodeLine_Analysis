use serde_json::json;
use tree_sitter::Node;
use serde::Serialize;
use std::env;
use std::fs::{ self, File };
use std::io::Write;
use tree_sitter::{ Language, Parser };
use std::collections::HashMap;
fn main() {
    match env::current_dir() {
        Ok(dir) => println!("Current directory is: {}", dir.display()),
        Err(e) => println!("Couldn't get current directory: {}", e),
    }

    let mut file = File::create("output.txt").expect("Unable to create file");
    let mut json_file = File::create("ast.json").expect("Unable to create file");

    let mut parser = Parser::new();
    let source_path = "../snake/src/main.rs";
    parser.set_language(tree_sitter_rust::language()).expect("Error loading Rust grammar");

    let source_code = fs
        ::read_to_string(source_path)
        .expect("Something went wrong reading the file");

    let tree = parser.parse(source_code.clone(), None).unwrap();
    let root_node = tree.root_node();

    println!("Syntax tree: {:?}", root_node);
    print_json_to_file(&root_node, &mut json_file, &parser, &source_code);
}


fn node_to_json(node: &Node, parser: &Parser, source_code: &str) -> serde_json::Value {
    let function_infos = process_node(node, parser, source_code);
    if !function_infos.is_empty() {
        let function_info_objects: Vec<serde_json::Value> = function_infos
            .into_iter()
            .map(|function_info| {
                json!({
                    "type": "function",
                    "name": function_info.name,
                    "module": function_info.module,
                    "start_line": function_info.start_line,
                    "end_line": function_info.end_line,
                })
            })
            .collect();
        json!({
            "type": "function_calls",
            "functions": function_info_objects,
        })
    } else {
        let start_pos = node.start_position();
        let end_pos = node.end_position();
        let mut children = Vec::new();
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            children.push(node_to_json(&child, parser, source_code));
        }
        json!({
            "type": node.kind(),
            "start_position": {"row": start_pos.row, "column": start_pos.column},
            "end_position": {"row": end_pos.row, "column": end_pos.column},
            "children": children
        })
    }
}


fn print_json_to_file(root_node: &Node, file: &mut File, parser: &Parser, source_code: &str) {
    let json = node_to_json(root_node, parser, source_code);
    write!(file, "{}", json.to_string()).expect("Unable to write to file");
}

fn utf8_text<'a>(node: &Node<'a>, _parser: &Parser, source_code: &'a str) -> &'a str {
    let start_byte = node.start_byte();
    let end_byte = node.end_byte();
    &source_code[start_byte..end_byte]
}

#[derive(Serialize)]
struct FunctionInfo {
    name: String,
    module: Option<String>,
    start_line: usize,
    end_line: usize,
}


fn process_node<'a>(
    node: &Node<'a>,
    _parser: &Parser,
    source_code: &'a str
) -> Vec<FunctionInfo> {
    println!("Processing node of kind: {}", node.kind());
    let mut function_infos = Vec::new();
    let mut imports = HashMap::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "use_declaration" {
            let import_text = utf8_text(&child, _parser, source_code);
            let parts: Vec<&str> = import_text.split("::").collect();
            if parts.len() == 2 {
                imports.insert(parts[1].to_string(), parts[0].to_string());
            }
        }
        if child.kind() == "call_expression" {
            let start_pos = child.start_position();
            let end_pos = child.end_position();
            if let Some(function_name_node) = child.child_by_field_name("identifier") {
                let function_name = utf8_text(&function_name_node, _parser, source_code).to_string();
                let module = if let Some(module_name_node) = child.child_by_field_name("module_name") {
                    let module_name = utf8_text(&module_name_node, _parser, source_code).to_string();
                    imports.get(&module_name).cloned()
                } else {
                    None
                };
                function_infos.push(FunctionInfo {
                    name: function_name,
                    module,
                    start_line: start_pos.row + 1,
                    end_line: end_pos.row + 1,
                });
            }
        }
    }
    function_infos
}