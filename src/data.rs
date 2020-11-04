use std::collections::HashMap;
use std::fmt::Display;

mod primitive;
pub mod tree_storage;

#[derive(Clone)]
pub struct DataValue {
    pub title: String,
    pub name: Vec<u8>,
    pub password: Vec<u8>,
    pub url: String,
    pub expire: u64,
    pub extra: HashMap<String, Vec<u8>>,
}

impl DataValue {
    pub fn new(title: &str, name: Vec<u8>, password: Vec<u8>) -> Self {
        DataValue {
            title: title.to_string(),
            name,
            password,
            url: String::new(),
            expire: 0,
            extra: HashMap::new(),
        }
    }
}

impl Display for DataValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: {}, {}-byte password",
            self.title,
            String::from_utf8_lossy(&self.name),
            self.password.len()
        )
    }
}

#[derive(Clone)]
pub struct NodeMeta {
    pub title: String,
}

impl NodeMeta {
    pub fn new(title: &str) -> Self {
        NodeMeta {
            title: title.to_string(),
        }
    }
}

impl Display for NodeMeta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.title)
    }
}

pub type TreeElement = tree_storage::Element<NodeMeta, DataValue>;

#[test]
fn test_data_constructing_and_display() {
    let node_meta = NodeMeta::new("some node info");
    let data_value = DataValue::new(
        "some data",
        b"data name".to_vec(),
        b"secret password".to_vec(),
    );
    let mut node = TreeElement::new_node(node_meta.clone());
    let data = TreeElement::new_data(data_value.clone());
    assert!(node.add_child(data).is_ok());
    // test Display
    assert_eq!(format!("{}", node_meta), "some node info");
    assert_eq!(
        format!("{}", data_value),
        "some data: data name, 15-byte password"
    );
    assert_eq!(format!("{}", node), "node: some node info, children: 1");
}
