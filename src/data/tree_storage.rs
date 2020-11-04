use serde::{Deserialize, Serialize};
use std::fmt::Display;

/// The parametrizing types can be assumed as Node **M**etadata and Data **V**alue
//#[derive(Serialize, Deserialize)]
pub enum Element<'de, M, V>
where
    M: Display + Serialize + Deserialize<'de>,
    V: Display + Serialize + Deserialize<'de>,
{
    Node(M, Vec<Element<'de, M, V>>),
    Data(V),
}

impl<'de, M: Display, V: Display> Element<'de, M, V>
where
    M: Display + Serialize + Deserialize<'de>,
    V: Display + Serialize + Deserialize<'de>,
{
    pub fn add_child(&mut self, node: Element<'de, M, V>) -> Result<(), String> {
        match self {
            Element::Data(_) => Err("cannot add child to data node".into()),
            Element::Node(ref _meta, ref mut children) => {
                children.push(node);
                Ok(())
            }
        }
    }

    pub fn new_data(value: V) -> Self {
        Element::Data(value)
    }

    pub fn new_node(meta: M) -> Self {
        Element::Node(meta, Vec::new())
    }

    pub fn size(&self) -> usize {
        match self {
            Element::Data(_) => 1, // itself
            Element::Node(ref _meta, ref children) => {
                // itself
                let mut cnt = 1;
                // children
                for c in children {
                    cnt += c.size();
                }
                cnt
            }
        }
    }

    pub fn is_node(&self) -> bool {
        match self {
            Element::Data(_) => false,
            Element::Node(_, _) => true,
        }
    }

    pub fn is_data(&self) -> bool {
        !self.is_node()
    }

    pub fn get_elem(&self, path: &[usize]) -> Option<&Self> {
        match self {
            Element::Data(_) => None,
            Element::Node(ref _meta, ref children) => match path.len() {
                0 => None,
                n => {
                    if path[0] < children.len() {
                        if n == 1 {
                            Some(&children[path[0]])
                        } else {
                            children[path[0]].get_elem(&path[1..])
                        }
                    } else {
                        None
                    }
                }
            },
        }
    }

    pub fn get_elem_mut(&mut self, path: &[usize]) -> Option<&mut Self> {
        match self {
            Element::Data(_) => None,
            Element::Node(ref _meta, ref mut children) => match path.len() {
                0 => None,
                n => {
                    if path[0] < children.len() {
                        if n == 1 {
                            Some(&mut children[path[0]])
                        } else {
                            children[path[0]].get_elem_mut(&path[1..])
                        }
                    } else {
                        None
                    }
                }
            },
        }
    }

    pub fn get_data(&self) -> Option<&V> {
        match self {
            Element::Data(value) => Some(&value),
            Element::Node(..) => None,
        }
    }
}

impl<'de, M, V> Display for Element<'de, M, V>
where
    M: Display + Serialize + Deserialize<'de>,
    V: Display + Serialize + Deserialize<'de>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Element::Data(ref d) => write!(f, "data {}", d),
            Element::Node(ref meta, ref children) => {
                write!(f, "node: {}, children: {}", meta, children.len())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Element;
    use serde::{Deserialize, Serialize};
    use std::fmt::Display;

    #[derive(Serialize, Deserialize)]
    pub struct TestValue {
        pub title: String,
        pub name: Vec<u8>,
        pub password: Vec<u8>,
    }

    impl TestValue {
        pub fn new(title: &str, name: Vec<u8>, password: Vec<u8>) -> Self {
            TestValue {
                title: title.to_string(),
                name,
                password,
            }
        }
    }

    impl Display for TestValue {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "TestValue")
        }
    }

    pub struct TestMeta {
        pub title: String,
    }

    impl TestMeta {
        pub fn new(title: &str) -> Self {
            TestMeta {
                title: title.to_string(),
            }
        }
    }

    impl Display for TestMeta {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "TestMeta")
        }
    }

    pub type TestElement = Element<'static, TestMeta, TestValue>;
}

#[test]
fn test_nodes_operations() {
    use tests::{TestElement, TestMeta, TestValue};
    // level 2
    let mut lvl2 = TestElement::new_node(TestMeta::new("lvl-2"));
    assert!(lvl2
        .add_child(TestElement::new_data(TestValue::new(
            "lvl-2-0",
            b"name-2-0".to_vec(),
            b"password-2-0".to_vec()
        )))
        .is_ok());
    assert!(lvl2
        .add_child(TestElement::new_node(TestMeta::new("lvl-2-1")))
        .is_ok());
    // level 1
    let mut lvl1 = TestElement::new_node(TestMeta::new("lvl-1"));
    assert!(lvl1
        .add_child(TestElement::new_data(TestValue::new(
            "lvl-1-0",
            b"name-1-0".to_vec(),
            b"password-1-0".to_vec()
        )))
        .is_ok());
    assert!(lvl1.add_child(lvl2).is_ok());
    // level 0
    let mut lvl0 = TestElement::new_node(TestMeta::new("lvl-0"));
    assert!(lvl0
        .add_child(TestElement::new_data(TestValue::new(
            "lvl0-0",
            b"name0-0".to_vec(),
            b"password0-0".to_vec()
        )))
        .is_ok());
    assert!(lvl0.add_child(lvl1).is_ok());

    // add more nodes directly
    assert!(lvl0
        .add_child(TestElement::new_node(TestMeta::new("lvl-0-1")))
        .is_ok());

    assert!(lvl0
        .add_child(TestElement::new_node(TestMeta::new("lvl-0-2")))
        .is_ok());

    // expected structure:
    // lvl0
    //  - lvl-0-0 (data)
    //  - lvl-1 (node)
    //      - lvl-1-0 (data)
    //      - lvl-2 (node)
    //          - lvl-2-0 (data)
    //          - lvl-2-1 (node)
    //  - lvl-0-1 (node)
    //  - lvl-0-2 (node)

    // read access to data node
    let maybe_lvl_0_0 = lvl0.get_elem(&[0]);
    assert!(maybe_lvl_0_0.is_some());
    let lvl_0_0 = maybe_lvl_0_0.unwrap();
    assert!(lvl_0_0.is_data());
    assert!(!lvl_0_0.is_node());
    match lvl_0_0 {
        Element::Node(..) => assert!(false),
        Element::Data(value) => {
            assert_eq!(value.title, "lvl0-0");
            assert_eq!(value.name, b"name0-0".to_vec());
            assert_eq!(value.password, b"password0-0".to_vec());
        }
    }

    // read access to arbitrary node
    let maybe_lvl_0_1 = lvl0.get_elem(&[2]);
    assert!(maybe_lvl_0_1.is_some());
    let lvl_0_1 = maybe_lvl_0_1.unwrap();
    assert!(lvl_0_1.is_node());
    assert!(!lvl_0_1.is_data());
    match lvl_0_1 {
        Element::Data(_) => assert!(false),
        Element::Node(meta, _) => assert_eq!(meta.title, "lvl-0-1"),
    }

    assert_eq!(lvl0.size(), 9);

    // add more nodes to arbirary child node
    let maybe_lvl_2_1 = lvl0.get_elem_mut(&[1, 1, 1]);
    assert!(maybe_lvl_2_1.is_some());
    let lvl_2_1 = maybe_lvl_2_1.unwrap();
    assert!(lvl_2_1.is_node());
    assert!(lvl_2_1
        .add_child(TestElement::new_node(TestMeta::new("lvl-3-0")))
        .is_ok());
    assert!(lvl_2_1
        .add_child(TestElement::new_data(TestValue::new(
            "lvl-3-1",
            b"name-3-1".to_vec(),
            b"password-3-1".to_vec(),
        )))
        .is_ok());

    // expected structure:
    // lvl0
    //  - lvl-0-0 (data)
    //  - lvl-1 (node)
    //      - lvl-1-0 (data)
    //      - lvl-2 (node)
    //          - lvl-2-0 (data)
    //          - lvl-2-1 (node)
    //              - lvl-3-0 (node)
    //              - lvl-3-1 (data)
    //  - lvl-0-1 (node)
    //  - lvl-0-2 (node)

    assert_eq!(lvl0.size(), 11);

    // test most recent child node content

    let lvl_3_1 = lvl0.get_elem(&[1, 1, 1, 1]).unwrap();
    assert!(lvl_3_1.is_data());
    match lvl_3_1 {
        Element::Data(ref v) => {
            assert_eq!(v.name, b"name-3-1".to_vec());
        }
        _ => assert!(false),
    }
}
