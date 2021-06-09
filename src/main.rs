mod cryptography;
mod node;

use cryptography::PublicKey;
use cryptography::SecretKey;
use node::Node;

use bindings::Windows::Win32::NetworkManagement::WiFi::WLAN_AVAILABLE_NETWORK_LIST;
use bindings::Windows::Win32::NetworkManagement::WiFi::WLAN_INTERFACE_INFO_LIST;
use bindings::Windows::Win32::NetworkManagement::WiFi::*;
use bindings::Windows::Win32::System::SystemServices::HANDLE;
use windows::Guid;

use std::ptr;
use std::thread;
use std::time::Duration;

fn main() -> windows::Result<()> {
    let mut handle = HANDLE(1);
    let mut client: *mut HANDLE = &mut handle;
    let mut interface: *mut WLAN_INTERFACE_INFO_LIST = ptr::null_mut();
    let mut avail_nets: *mut WLAN_AVAILABLE_NETWORK_LIST = ptr::null_mut();
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

        let ret =
            WlanGetAvailableNetworkList(*client, guid, 0u32, ptr::null_mut(), &mut avail_nets);

        /* I'm guessing you're trying to do a regular Rustlike index, or dereference the pointer into a variable
        which won't work because the structure's actually variable-sized; the header says the array is of size 1 but the extra items are past the end of the struct, and you have to use pointer math to find them
        getting the nth network would look like seri — Today at 20:17
        */

        for i in 0..(*avail_nets).dwNumberOfItems {
            println!(
                "{:?}\n",
                *(ptr::addr_of!((*avail_nets).Network).offset(i as isize))
            );
        }

        thread::sleep(Duration::from_millis(150000000));
    }

    Ok(())
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
