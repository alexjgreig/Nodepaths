pub struct User {
    pub username: String,
    pub EccKey: String,
    pub IPv4: String,
}
impl User {

    pub fn new(username: String) {
        User {
            username: username,
            EccKey: create_ecc_key()
            IPv4: create_ipv4()
    }
    pub fn store_credentials(&self) {}
}

fn create_ecc_key() {}

fn create_ipv4() {}
