mod data;
mod mock_data;

fn main() {
    println!("Hello, world!");
    let root = mock_data::get_mock_data();
    let json = serde_json::to_string(&root).unwrap();
    println!("{}", &json);
    let root_restored = serde_json::from_str::<data::TreeElement>(&json).unwrap();
    if root == root_restored {
        println!("Deserializing OK, bye");
    } else {
        println!("Deserializing failed, bye");
    }
}
