use tree_sitter::{Language, Parser};
use std::fs;
use std::env;
fn main() {
    match env::current_dir() {
        Ok(dir) => println!("Current directory is: {}", dir.display()),
        Err(e) => println!("Couldn't get current directory: {}", e),
    }

    let mut parser = Parser::new();
    let source_path = "../snake/src/main.rs";
    parser
        .set_language(tree_sitter_rust::language())
        .expect("Error loading Rust grammar");
        
        let source_code = fs::read_to_string(source_path)
        .expect("Something went wrong reading the file");
    
    let tree = parser.parse(source_code, None).unwrap();
    let root_node = tree.root_node();

    println!("Syntax tree: {:?}", root_node);
    print_node(root_node, 0);

    fn print_node(node: tree_sitter::Node, indent_level: usize) {
        let indent: String = "  ".repeat(indent_level);
        println!("{}Node type: {}", indent, node.kind());
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            print_node(child, indent_level + 1);
        }
    }
}
