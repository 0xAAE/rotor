use crate::data::{DataValue, NodeMeta, TreeElement};

const EMAIL: &str = "aae@google.com";
const LOGIN: &str = "AAE";
const PWD: [&str; 6] = [
    "GaSmTgpWs5",
    "VxLPtwZG44",
    "3jgn4UNPU7",
    "6QmTh9Lyso",
    "fA7snQCnv",
    "5YqM39PgL",
];
const IDX_BOOKING: usize = 0;
const IDX_EBAY: usize = 1;
const IDX_CRATES: usize = 2;
const IDX_GITHUB: usize = 3;
const IDX_GOOGLE: usize = 4;
const IDX_NOTEBOOK: usize = 5;

fn create_mock_data() -> Result<TreeElement, String> {
    // services: booking, ebay
    let mut services = TreeElement::new_node(NodeMeta::new("Services"));
    // booking
    services.add_child(TreeElement::new_data(DataValue::new_site(
        "Booking",
        LOGIN.as_bytes().to_vec(),
        PWD[IDX_BOOKING].as_bytes().to_vec(),
        "https://www.booking.com",
    )))?;
    // ebay
    services.add_child(TreeElement::new_data(DataValue::new_site(
        "Ebay",
        LOGIN.as_bytes().to_vec(),
        PWD[IDX_EBAY].as_bytes().to_vec(),
        "https://www.ebay.com",
    )))?;

    // development: crates.io, github.com
    let mut development = TreeElement::new_node(NodeMeta::new("Development"));
    // crates.io
    development.add_child(TreeElement::new_data(DataValue::new_site(
        "Crates.io",
        LOGIN.as_bytes().to_vec(),
        PWD[IDX_CRATES].as_bytes().to_vec(),
        "https://www.crates.io",
    )))?;
    // crates.io
    development.add_child(TreeElement::new_data(DataValue::new_site(
        "GitHub",
        LOGIN.as_bytes().to_vec(),
        PWD[IDX_GITHUB].as_bytes().to_vec(),
        "https://www.github.com",
    )))?;

    // accounts: services, development, google
    let mut accounts = TreeElement::new_node(NodeMeta::new("Accounts"));
    // services
    accounts.add_child(services)?;
    // development
    accounts.add_child(development)?;
    // google
    accounts.add_child(TreeElement::new_data(DataValue::new_site(
        "Google",
        EMAIL.as_bytes().to_vec(),
        PWD[IDX_GOOGLE].as_bytes().to_vec(),
        "https://google.com",
    )))?;

    // private: accounts, notebook
    let mut private = TreeElement::new_node(NodeMeta::new("Private"));
    // accounts
    private.add_child(accounts)?;
    // notebook
    private.add_child(TreeElement::new_data(DataValue::new(
        "Notebook",
        LOGIN.as_bytes().to_vec(),
        PWD[IDX_NOTEBOOK].as_bytes().to_vec(),
    )))?;

    Ok(private)
}

pub fn get_mock_data() -> TreeElement {
    let mut root = TreeElement::new_node(NodeMeta::new("Mock data"));
    if let Ok(nodes) = create_mock_data() {
        let _ = root.add_child(nodes);
    }
    root
}

#[test]
fn test_get_mock_data() {
    let mock = get_mock_data();
    assert!(mock.is_node());
    // + (0) mock:
    //     + (0) private:
    //         + (0) accounts:
    //             + (0) services
    //                 = (0) booking
    //                 = (1) ebay
    //             + (1) development
    //                 = (0) crates.io
    //                 = (0) github
    //             = (2) google
    //         = (1) notebook
    assert_eq!(mock.size(), 11);
    assert_eq!(
        mock.get_elem(&[0, 0, 0, 0])
            .unwrap()
            .get_data()
            .unwrap()
            .title,
        "Booking"
    );
}
