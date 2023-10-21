use serde_json::{ json, Value };
use tree_sitter::{ Node, Parser, Point };
use std::fs::{ self, File };
use std::io::Write;
use walkdir::WalkDir;
use std::path::Path;
use std::collections::HashMap;

fn main() {
    let dir = "../snake/src"; // Replace with the root directory of your Rust project
    let rust_files = discover_rust_files(dir);

    let mut parser = Parser::new();
    parser.set_language(tree_sitter_rust::language()).expect("Error loading Rust grammar");

    let mut json_file = File::create("ast.json").expect("Unable to create file");
    let mut outer_json = json!({});

    for file in rust_files {
        println!("{}", file);

        let source_code = fs::read_to_string(&file).expect("Something went wrong reading the file");
        let tree = parser.parse(&source_code, None).unwrap();
        let root_node = tree.root_node();

        let mut node_type_map: HashMap<String, Vec<(Point, Point, String, Vec<Value>)>> = HashMap::new();
        let json = node_to_json(&root_node, &source_code, &mut node_type_map);

        // Adding a new key-value pair for each file
        outer_json[file] = json;

        // Print out the node_type_map for debugging
        println!("{:#?}", node_type_map.keys());
    }

    write!(json_file, "{}", outer_json.to_string()).expect("Unable to write to file");
}

fn utf8_text<'a>(node: &Node<'a>, source_code: &'a str) -> &'a str {
    let start_byte = node.start_byte();
    let end_byte = node.end_byte();
    &source_code[start_byte..end_byte]
}

fn node_to_json(
    node: &Node,
    source_code: &str,
    node_type_map: &mut HashMap<String, Vec<(Point, Point, String, Vec<Value>)>>
) -> Value {
    // change this to false to include all nodes in the JSON
    const EXPRESSION_AND_ABOVE_ONLY: bool = true;

    let node_type = node.kind();
    let start_pos = node.start_position();
    let end_pos = node.end_position();
    let text = utf8_text(node, source_code);
    let mut children = Vec::new();
    let mut cursor = node.walk();

    // Process child nodes
    for child in node.children(&mut cursor) {
        let child_json = node_to_json(&child, source_code, node_type_map);
        if !EXPRESSION_AND_ABOVE_ONLY || child_json != Value::Null {
            children.push(child_json);
        }
    }

    if let Some(node_type_array) = node_type_map.get_mut(node_type) {
        // If the node type is already present, add the new data to the existing array
        node_type_array.push((start_pos, end_pos, text.to_string(), children.clone()));
    } else {
        // If the node type is not present, create a new array and add the data to it
        let mut new_node_type_array = Vec::new();
        new_node_type_array.push((start_pos, end_pos, text.to_string(), children.clone()));
        node_type_map.insert(node_type.to_string(), new_node_type_array);
    }

    // If EXPRESSION_AND_ABOVE_ONLY is true, only include nodes of the specified types and expressions
    if
        EXPRESSION_AND_ABOVE_ONLY &&
        !node_type.contains("expression") &&
        node_type != "source_file" &&
        node_type != "function_item" &&
        node_type != "block"
    {
        return Value::Null;
    }

    json!({
        "type": node_type,
        "start_position": {"row": start_pos.row, "column": start_pos.column},
        "end_position": {"row": end_pos.row, "column": end_pos.column},
        "text": text,
        "children": children  // Now, this line won't cause an error since 'children' hasn't been moved.
    })
}

fn discover_rust_files(dir: &str) -> Vec<String> {
    let mut rust_files = Vec::new();
    for entry in WalkDir::new(dir) {
        match entry {
            Ok(entry) => {
                let path = entry.path();
                if path.extension() == Some(Path::new("rs").as_os_str()) {
                    rust_files.push(path.display().to_string());
                }
            }
            Err(err) => eprintln!("Error: {}", err),
        }
    }
    rust_files
}
