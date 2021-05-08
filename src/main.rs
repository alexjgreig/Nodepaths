mod user;
mod x25519;

use user::User;
use x25519::PublicKey;
use x25519::SecretKey;

fn main() {
    let user: User = User::load_user();
    let their_public: PublicKey = PublicKey::from([0u8; 32]);
    let shared_secret = SecretKey::from(user.keys.secret_key).diffie_hellman(&their_public);
    let enc_msg = shared_secret.encrypt("Hello".to_string());
    println!("{:?}", &enc_msg);
    let dec_msg = shared_secret.decrypt(enc_msg);
    println!("{}", dec_msg);
}
