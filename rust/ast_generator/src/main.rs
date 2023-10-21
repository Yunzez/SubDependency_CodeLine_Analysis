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

    let source_code = fs
        ::read_to_string(source_path)
        .expect("Something went wrong reading the file");

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
    // change this to false to include all nodes in the JSON
    const EXPRESSION_AND_ABOVE_ONLY: bool = true;

    let node_type = node.kind();
    let start_pos = node.start_position();
    let end_pos = node.end_position();
    let text = utf8_text(node, source_code);
    let mut children = Vec::new();
    let mut cursor = node.walk();
    
    // If EXPRESSION_AND_ABOVE_ONLY is true, only include nodes of the specified types and expressions
    if
        EXPRESSION_AND_ABOVE_ONLY &&
        !node_type.contains("expression") &&
        node_type != "source_file" &&
        node_type != "function_item" &&
        node_type != "block"
    {
        return serde_json::Value::Null;
    }

    for child in node.children(&mut cursor) {
        let child_json = node_to_json(&child, source_code);
        // Only add child JSON if it has the desired types or if the filter is off
        if !EXPRESSION_AND_ABOVE_ONLY {
            children.push(child_json);
        } else if child_json != serde_json::Value::Null {
            children.push(child_json);
        }
    }

    json!({
        "type": node_type,
        "start_position": {"row": start_pos.row, "column": start_pos.column},
        "end_position": {"row": end_pos.row, "column": end_pos.column},
        "text": text,
        "children": children
    })
}
