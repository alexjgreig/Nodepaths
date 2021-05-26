mod cryptography;
mod node;

use cryptography::PublicKey;
use cryptography::SecretKey;
use node::Node;

fn main() {
    println!("hello");
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn load_node_config() {
        let node: Node = Node::load_node();
    }
    #[test]
    fn encrypt_decrypt_roundtrip() {
        let node: Node = Node::load_node();
        let original_message = "Hello".to_string();
        let their_public: PublicKey = PublicKey::from([0u8; 32]);
        let shared_secret = SecretKey::from(node.keys.secret_key).diffie_hellman(&their_public);
        let enc_msg = shared_secret.encrypt(original_message.clone());
        let dec_msg = shared_secret.decrypt(enc_msg);
        assert_eq!(
            original_message.clone(),
            dec_msg.trim_end_matches(char::from(0))
        );
    }
}
