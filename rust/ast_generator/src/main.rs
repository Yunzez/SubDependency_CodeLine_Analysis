use serde_json::json;
use tree_sitter::Node;
use std::env;
use std::fs::{self, File};
use std::io::Write;
use tree_sitter::{Language, Parser};
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

    let tree = parser.parse(source_code, None).unwrap();
    let root_node = tree.root_node();

    println!("Syntax tree: {:?}", root_node);
    print_node(root_node, 0);
    print_node_to_file(root_node, 0, &mut file);
    print_json_to_file(&root_node, &mut json_file);

}


fn print_node(node: tree_sitter::Node, indent_level: usize) {
    let indent: String = "  ".repeat(indent_level);
    let start_pos = node.start_position();
    let end_pos = node.end_position();
    println!(
        "{}Node type: {} ({}:{}-{}:{})",
        indent,
        node.kind(),
        start_pos.row,
        start_pos.column,
        end_pos.row,
        end_pos.column
    );
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        print_node(child, indent_level + 1);
    }
}

fn print_node_to_file(node: tree_sitter::Node, indent_level: usize, file: &mut File) {
    let indent: String = "  ".repeat(indent_level);
    let start_pos = node.start_position();
    let end_pos = node.end_position();
    writeln!(
        file,
        "{}Node type: {} ({}:{}-{}:{})",
        indent,
        node.kind(),
        start_pos.row,
        start_pos.column,
        end_pos.row,
        end_pos.column
    ).expect("Unable to write to file");
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        print_node_to_file(child, indent_level + 1, file);
    }
}

fn node_to_json(node: &Node) -> serde_json::Value {
    let start_pos = node.start_position();
    let end_pos = node.end_position();
    let mut children = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        children.push(node_to_json(&child));
    }
    json!({
        "type": node.kind(),
        "start_position": {"row": start_pos.row, "column": start_pos.column},
        "end_position": {"row": end_pos.row, "column": end_pos.column},
        "children": children
    })
}

fn print_json_to_file(root_node: &Node, file: &mut File) {
    let json = node_to_json(root_node);
    write!(file, "{}", json.to_string()).expect("Unable to write to file");
}