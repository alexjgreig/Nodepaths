mod cryptography;
mod node;
mod socket_reader_writer;

use cryptography::PublicKey;
use cryptography::SecretKey;
use node::Config;
use node::Node;

use std::convert::TryFrom;
use std::io::{stdin, stdout, Write};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use windows::HSTRING;

use tokio_test;

#[tokio::main]
async fn main() {
    //title
    println!(
        "
███╗   ██╗ ██████╗ ██████╗ ███████╗██████╗  █████╗ ████████╗██╗  ██╗███████╗
████╗  ██║██╔═══██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗╚══██╔══╝██║  ██║██╔════╝
██╔██╗ ██║██║   ██║██║  ██║█████╗  ██████╔╝███████║   ██║   ███████║███████╗
██║╚██╗██║██║   ██║██║  ██║██╔══╝  ██╔═══╝ ██╔══██║   ██║   ██╔══██║╚════██║
██║ ╚████║╚██████╔╝██████╔╝███████╗██║     ██║  ██║   ██║   ██║  ██║███████║
╚═╝  ╚═══╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝
_____________________________________________________________________________
_____________________________________________________________________________
\n\n\n

Select an option:

(1) Advertise
(2) Connect
"
    );
    //gets user input for selection
    let mut input = String::new();
    stdin().read_line(&mut input).unwrap();
    let selection = input.trim().to_string();

    //boolean value for created yet

    let mut created_node = false;

    //outside while loop for creation of node, breaks if has been created and everything else has
    //broken
    while created_node == false {
        //Advertiser
        if selection == "1" {
            let node: Node = Node::new(true).await;
            created_node = true;
            loop {
                if Arc::clone(&node.connected_devices).lock().unwrap().len() > 0 {
                    println!("Please input a message to send: type quit to exit");
                    let mut input = String::new();
                    stdin().read_line(&mut input).unwrap();
                    let selection = input.trim().to_string();
                    //User quits program
                    if selection == "quit" {
                        break;
                    }
                    //Send message to other machine
                    node.send_message(HSTRING::try_from(input).unwrap());
                }
            }
            // Connector
        } else if selection == "2" {
            let node: Node = Node::new(false).await;
            created_node = true;
            loop {
                if Arc::clone(&node.discovered_devices).lock().unwrap().len() > 0 {
                    node.connect().await;
                    thread::sleep(Duration::from_millis(3000));
                    println!("Please input a message to send: type quit to exit");
                    let mut input = String::new();
                    stdin().read_line(&mut input).unwrap();
                    let selection = input.trim().to_string();
                    //user quites program
                    if selection == "quit" {
                        break;
                    }
                    //Send message to other machine
                    node.send_message(HSTRING::try_from(input).unwrap());
                }
            }
        } else {
            println!("please enter a valid input");
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // loads node config from a file or creates a new file if not avaliable.
    #[test]
    fn load_node_config() {
        let config: Config = Config::load_config();
    }
    #[test]
    // Encryption and Decryption Roundtrip - encrypts then decrypts and the starting message needs
    // to match to the message after the round trip
    fn encrypt_decrypt_roundtrip() {
        let config: Config = Config::load_config();
        let original_message = "Hello".to_string();
        let their_public: PublicKey = PublicKey::from([0u8; 32]);
        let shared_secret = SecretKey::from(config.keys.secret_key).diffie_hellman(&their_public);
        let enc_msg = shared_secret.encrypt(original_message.clone());
        let dec_msg = shared_secret.decrypt(enc_msg);
        assert_eq!(
            original_message.clone(),
            dec_msg.trim_end_matches(char::from(0))
        );
    }
    //Advertiser node creation - Uses boolean to specificy that it is this variant.
    #[test]
    fn advertiser_node_creation() {
        let node: Node = tokio_test::block_on(Node::new(true));
    }

    //Connector node creation - Uses boolean to specificy that it is this variant.
    #[test]
    fn connector_node_creation() {
        let node: Node = tokio_test::block_on(Node::new(false));
    }
}
/*
    Deprecated due to windows changing network driver model,
    replacing NDIS driver and associated SoftAP APIs with WDI driver model.
    Win32 is now replaced with UWP or WinRT and is be currently used.

let mut handle = HANDLE(1);
let mut client: *mut HANDLE = &mut handle;
let mut interface: *mut WLAN_INTERFACE_INFO_LIST = ptr::null_mut();
let mut avail_nets: *mut WLAN_AVAILABLE_NETWORK_LIST = ptr::null_mut();
let mut wlan_bss_list: *mut WLAN_BSS_LIST = ptr::null_mut();
let mut host_fail_reason: *mut WLAN_HOSTED_NETWORK_REASON = ptr::null_mut();
unsafe {
    let value = WlanOpenHandle(1u32, ptr::null_mut(), &mut 1u32, client);
    let result = WlanEnumInterfaces(*client, ptr::null_mut(), &mut interface);

    for i in 0..(*interface).dwNumberOfItems {
        println!(
            "{:?}\n",
            *(ptr::addr_of!((*interface).InterfaceInfo).offset(i as isize))
        );
    }

    let guid: *const Guid = &((*interface).InterfaceInfo[0].InterfaceGuid);

    println!("{:?}", *host_fail_reason);

    thread::sleep(Duration::from_millis(10000));
    let ret =
        WlanGetAvailableNetworkList(*client, guid, 1u32, ptr::null_mut(), &mut avail_nets);

    for i in 0..(*avail_nets).dwNumberOfItems {
        let dot11Ssid: DOT11_SSID =
            (*(ptr::addr_of!((*avail_nets).Network).offset(i as isize)))[0].dot11Ssid;
        let dot11BssType: DOT11_BSS_TYPE =
            (*(ptr::addr_of!((*avail_nets).Network).offset(i as isize)))[0].dot11BssType;
        let bss = WlanGetNetworkBssList(
            *client,
            guid,
            &dot11Ssid,
            dot11BssType,
            true,
            ptr::null_mut(),
            &mut wlan_bss_list,
        );
        println!("{:?}", *wlan_bss_list);
    }

    thread::sleep(Duration::from_millis(10000));
    mem::drop(interface);
    mem::drop(avail_nets);
    mem::drop(wlan_bss_list);
    mem::drop(guid);
    WlanCloseHandle(*client, ptr::null_mut());
}
    */
