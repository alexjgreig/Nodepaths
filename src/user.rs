use crate::x25519::{PublicKey, SecretKey, SharedSecret};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io;
use std::io::{Read, Write};

#[derive(Serialize, Deserialize)]
pub struct Keys {
    pub secret_key: [u8; 32],
    pub public_key: [u8; 32],
}

#[derive(Serialize, Deserialize)]
pub struct User {
    pub username: String,
    pub keys: Keys,
    pub ipv4: String,
}

impl User {
    pub fn load_user() -> Self {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open("src/config.toml")
            .expect("Couldn't open config file.");

        let mut contents = String::new();

        file.read_to_string(&mut contents).unwrap();
        let user: User = match toml::from_str(&contents) {
            Err(_) => create_user_config(),
            Ok(user) => user,
        };

        return user;
    }

    pub fn create_shared_secret(&self, their_public: &PublicKey) -> SharedSecret {
        return SecretKey::from(self.keys.secret_key).diffie_hellman(their_public);
    }
}
pub fn create_user_config() -> User {
    let user = User {
        username: get_username(),
        keys: create_ecc_keys(),
        ipv4: create_ipv4(),
    };

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .open("src/config.toml")
        .expect("Couldn't create TOML file.");
    file.write(toml::Value::try_from(&user).unwrap().to_string().as_bytes());

    return user;
}

fn get_username() -> String {
    let mut input = String::new();
    println!("Please enter a username: ");
    io::stdin().read_line(&mut input).unwrap();
    return input.trim().to_string();
}

fn create_ecc_keys() -> Keys {
    let secret_key: SecretKey = SecretKey::new();
    Keys {
        secret_key: secret_key.to_bytes(),
        public_key: PublicKey::from(&secret_key).to_bytes(),
    }
}

fn create_ipv4() -> String {
    return "192.168.458.345".to_string();
}
