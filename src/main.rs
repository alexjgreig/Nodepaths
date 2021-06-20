mod cryptography;
mod node;
mod socket_reader_writer;

use cryptography::PublicKey;
use cryptography::SecretKey;
use node::Config;
use node::Node;

use std::io::{stdin, stdout, Write};

#[tokio::main]
async fn main() {
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
    let mut input = String::new();
    stdin().read_line(&mut input).unwrap();
    let selection = input.trim().to_string();

    let mut created_node = false;

    while created_node == false {
        if selection == "1" {
            let node: Node = Node::new(true).await;
            created_node = true;
        } else if selection == "2" {
            let node: Node = Node::new(false).await;
            created_node = true;
        } else {
            println!("please enter a valid input");
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn load_node_config() {
        let config: Config = Config::load_config();
    }
    #[test]
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
