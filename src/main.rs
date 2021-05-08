mod node;
mod x25519;

use node::Node;
use x25519::PublicKey;
use x25519::SecretKey;

fn main() {
    let node: Node = Node::load_node();
    let their_public: PublicKey = PublicKey::from([0u8; 32]);
    let shared_secret = SecretKey::from(node.keys.secret_key).diffie_hellman(&their_public);
    let enc_msg = shared_secret.encrypt("Hello".to_string());
    println!("{:?}", &enc_msg);
    let dec_msg = shared_secret.decrypt(enc_msg);
    println!("{}", dec_msg);
}
