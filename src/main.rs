mod data;
mod mock_data;

fn main() {
    println!("Hello, world!");
    let root = mock_data::get_mock_data();
    let json = serde_json::to_string(&root).unwrap();
    println!("{}", json);
}
