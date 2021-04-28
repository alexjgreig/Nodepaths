mod ecc;

use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io;
use std::io::{Read, Write};
use ecc::{PublicKey, StaticSecret}
use rand_core::OsRng;

#[derive(Serialize, Deserialize)]
pub struct Keys {
    public: Option<StaticSecret>,
    private: Option<PublicKey>,
}

#[derive(Serialize, Deserialize)]
pub struct User {
    pub username: String,
    pub keys: Keys,
    pub ipv4: String,
}

impl User {
    pub fn new(username: String) -> Self {
        User {
            username: get_username(),
            keys: create_ecc_key(),
            ipv4: create_ipv4(),
        }
    }
    pub fn create_user_config(&self) {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .open("config.toml")
            .expect("Couldn't create TOML file.");
        file.write(toml::to_string(&self).unwrap().as_bytes());
    }

    pub fn load_user_config(&mut self) {
        let mut file = OpenOptions::new()
            .read(true)
            .create(true)
            .open("config.toml")
            .expect("Couldn't open config file.");

        let mut contents = String::new();

        file.read_to_string(&mut contents).unwrap();
        *self = toml::from_str(&contents).unwrap();
    }
}

fn get_username() -> String {
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    return input.trim().to_string();
}

fn create_ecc_key() -> Keys {
    let private: StaticSecret = StaticSecret::new(OsRng::new())
    Keys {
        public: Some("DFSFSF".to_string()),
        private: private,
    }
}

fn create_ipv4() -> String {
    return "hello".to_string();
}
