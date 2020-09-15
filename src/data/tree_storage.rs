use std::collections::HashMap;
use std::fmt::Display;

pub struct Item {
    pub title: String,
    pub name: Vec<u8>,
    pub password: Vec<u8>,
    pub url: String,
    pub expire: u64,
    pub extra: HashMap<String, Vec<u8>>,
}

pub struct NodeMeta {
    pub title: String,
}

pub enum Node {
    Child { meta: NodeMeta, storage: Storage },
    Data(Item),
}

impl Node {
    pub fn add_child(&mut self, node: Node) -> Result<(), String> {
        match self {
            Node::Data(_) => Err("cannot add child to data node".to_string()),
            Node::Child {
                ref mut storage, ..
            } => {
                storage.add(node);
                Ok(())
            }
        }
    }

    pub fn new_data(data: Item) -> Self {
        Node::Data(data)
    }

    pub fn new_node(meta: NodeMeta) -> Self {
        Node::Child {
            meta,
            storage: Storage::new(),
        }
    }

    pub fn total_count(&self) -> usize {
        match self {
            Node::Data(_) => 1, // itself
            Node::Child { ref storage, .. } => {
                // itself
                let mut cnt = 1;
                // children
                for c in &storage.nodes {
                    cnt += c.total_count();
                }
                cnt
            }
        }
    }
}

impl Display for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Node::Data(ref d) => write!(f, "data {}", d.title),
            Node::Child {
                ref meta,
                ref storage,
            } => write!(f, "node {}, {} children", meta.title, storage.nodes.len()),
        }
    }
}

pub struct Storage {
    pub nodes: Vec<Node>,
}

impl Storage {
    pub fn new() -> Self {
        Storage { nodes: Vec::new() }
    }

    pub fn add(&mut self, node: Node) {
        self.nodes.push(node);
    }
}

#[test]
fn test_nodes_construction() {
    // level 2
    let mut lvl2 = Node::new_node(NodeMeta {
        title: "lvl-2".to_string(),
    });
    assert!(lvl2
        .add_child(Node::new_data(Item {
            title: "lvl-2-0".to_string(),
            name: b"name-2-0".to_vec(),
            password: b"password-2-0".to_vec(),
            url: "url-2-0".to_string(),
            expire: 0,
            extra: HashMap::new(),
        }))
        .is_ok());
    assert!(lvl2
        .add_child(Node::new_node(NodeMeta {
            title: "lvl-2-1".to_string()
        }))
        .is_ok());
    // level 1
    let mut lvl1 = Node::new_node(NodeMeta {
        title: "lvl-1".to_string(),
    });
    assert!(lvl1
        .add_child(Node::new_data(Item {
            title: "lvl-1-0".to_string(),
            name: b"name-1-0".to_vec(),
            password: b"password-1-0".to_vec(),
            url: "url-1-0".to_string(),
            expire: 0,
            extra: HashMap::new(),
        }))
        .is_ok());
    assert!(lvl1.add_child(lvl2).is_ok());
    // level 0
    let mut lvl0 = Node::new_node(NodeMeta {
        title: "lvl-0".to_string(),
    });
    assert!(lvl0
        .add_child(Node::new_data(Item {
            title: "lvl0-0".to_string(),
            name: b"name0-0".to_vec(),
            password: b"password0-0".to_vec(),
            url: "url0-0".to_string(),
            expire: 0,
            extra: HashMap::new(),
        }))
        .is_ok());
    assert!(lvl0.add_child(lvl1).is_ok());

    // add in future

    assert!(lvl0
        .add_child(Node::new_node(NodeMeta {
            title: "lvl-0-1".to_string(),
        }))
        .is_ok());

    assert!(lvl0
        .add_child(Node::new_node(NodeMeta {
            title: "lvl-0-2".to_string(),
        }))
        .is_ok());

    // lvl0
    //  - lvl-0-0 (data)
    //  - lvl-1 (node)
    //      - lvl-1-0 (data)
    //      - lvl-2 (node)
    //          - lvl-2-0 (data)
    //          - lvl-2-1 (node)
    //  - lvl-0-1 (node)
    //  - lvl-0-2 (node)

    assert_eq!(lvl0.total_count(), 9);
}
