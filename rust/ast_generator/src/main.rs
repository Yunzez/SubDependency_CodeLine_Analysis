use serde_json::json;
use tree_sitter::Node;
use serde::Serialize;
use std::env;
use std::fs::{ self, File };
use std::io::Write;
use tree_sitter::{ Parser };

fn main() {
    let mut json_file = File::create("ast.json").expect("Unable to create file");

    let mut parser = Parser::new();
    let source_path = "../snake/src/main.rs";
    parser.set_language(tree_sitter_rust::language()).expect("Error loading Rust grammar");

    let source_code = fs::read_to_string(source_path).expect("Something went wrong reading the file");

    let tree = parser.parse(&source_code, None).unwrap();
    let root_node = tree.root_node();

    let json = node_to_json(&root_node, &source_code);

    write!(json_file, "{}", json.to_string()).expect("Unable to write to file");
}


fn utf8_text<'a>(node: &Node<'a>, source_code: &'a str) -> &'a str {
    let start_byte = node.start_byte();
    let end_byte = node.end_byte();
    &source_code[start_byte..end_byte]
}

fn node_to_json(node: &Node, source_code: &str) -> serde_json::Value {
    let start_pos = node.start_position();
    let end_pos = node.end_position();
    let mut children = Vec::new();
    let text = utf8_text(node, source_code);
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        children.push(node_to_json(&child, source_code));
    }
    json!({
        "type": node.kind(),
        "start_position": {"row": start_pos.row, "column": start_pos.column},
        "end_position": {"row": end_pos.row, "column": end_pos.column},
        "text": text,
        "children": children
    })
}


#[derive(Serialize)]
struct FunctionInfo {
    name: String,
    module: Option<String>,
    start_line: usize,
    end_line: usize,
    called_functions: Vec<String>,
}

#[derive(Serialize)]
struct ModuleInfo {
    module_name: String,
}
