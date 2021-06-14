mod cryptography;
mod node;
mod socket_reader_writer;

use cryptography::PublicKey;
use cryptography::SecretKey;
use node::Node;
use socket_reader_writer::SocketReaderWriter;

use bindings::Windows::Devices::Enumeration::DeviceInformationCollection  
use bindings::Windows::Devices::Enumeration::DeviceInformation;  
use bindings::Windows::Devices::Enumeration::DeviceInformationElement;
use bindings::Windows::Devices::Enumeration::DeviceInformationCustomPairing;
use bindings::Windows::Devices::Enumeration::DevicePairingKinds;
use bindings::Windows::Devices::Enumeration::DevicePairingProtectionLevel;
use bindings::Windows::Devices::Enumeration::DevicePairingResult;
use bindings::Windows::Devices::Enumeration::DevicePairingResultStatus;
use bindings::Windows::Devices::Enumeration::*;
use bindings::Windows::Devices::WiFiDirect::DeviceInformationPairing;
use bindings::Windows::Devices::WiFiDirect::WiFiDirectAdvertisementPublisher;
use bindings::Windows::Devices::WiFiDirect::WiFiDirectAdvertisementPublisherStatus;
use bindings::Windows::Devices::WiFiDirect::WiFiDirectAdvertisementPublisherStatusChangedEventArgs;
use bindings::Windows::Devices::WiFiDirect::WiFiDirectConnectionListener;
use bindings::Windows::Devices::WiFiDirect::WiFiDirectConnectionParameters;
use bindings::Windows::Devices::WiFiDirect::WiFiDirectConnectionRequest;
use bindings::Windows::Devices::WiFiDirect::WiFiDirectDevice;
use bindings::Windows::Foundation::*;
use bindings::Windows::Foundation::Collections::IVectorView;
use bindings::Windows::Networking::Sockets::*;
use bindings::Windows::Networking::EndpointPair;
use bindings::Windows::Networking::Sockets::StreamSocket;
use bindings::Windows::Networking::Sockets::StreamSocketListener;
use bindings::Windows::Networking::Sockets::StreamSocketListenerConnectionReceivedEventArgs;

use windows::HSTRING;

use std::mem;
use std::ptr;
use std::thread;
use std::time::Duration;
std::collections::HashMap

use futures::future::Future;

struct ConnectedDevice(display_name_in: HSTRING, wfd_device_in: WiFiDirectDevice, socket_rw_in: &SocketReaderWriter);

//TODO: MOVE ADVERTISER INTO SEPARATE CLASS

struct Advertiser;

impl Advertiser {

    fn start() {

    //LISTENER
    let str_server_port = "50001";
    let information_elements: Vec<WiFiDirectInformationElement> = Vec::new();

    let publisher: WiFiDirectAdvertisementPublisher = WiFiDirectAdvertisementPublisher::new()?;

    let statusChangedToken =
        publisher.StatusChanged(&TypedEventHandler::new(Advertiser::on_status_changed));

    let listener: WiFiDirectConnectionListener = WiFiDirectConnectionListener::new()?;
    listener.ConnectionRequested(&TypedEvenHandler::new(Advertiser::on_connection_requested));

    let pending_connections: HashMap<StreamSocketListener, WiFiDirectDevice> = HashMap::new();

    let connected_devices: Vec<ConnectedDevice> = Vec::new();

     Let discoverability = GetSelectedItemTag<WiFiDirectAdvertisementListenStateDiscoverability>(cmbListenState());
     publisher.Advertisement().ListenStateDiscoverability(discoverability);

    //Add information Elements
     publisher.Advertisement().InformationElements().ReplaceAll(information_elements);
     publisher.Start();
      if (publisher.Status() == WiFiDirectAdvertisementPublisherStatus::Started)
        {
            println!("Advertisment Started.");

      } else {

            println!("Advertisment Failed: Code {:?}", publisher.Status());
      }


    }

    fn stop(&self) {
        &self.publisher.Stop();
        &self.publisher.StatusChanged(status_changed_token);
        &self.listener.ConnectionRequested(connection_requested_token);
         
        &self.information_elements.clear();
        
        println!("Advertisment Stopped Successfully")
    }
    fn on_status_changed(
        sender: &Option<WiFiDirectAdvertisementPublisher>,
        e: &Option<WiFiDirectAdvertisementPublisherStatusChangedEventArgs>,
    ) -> windows::Result<()> {
        // body of your event handler
        if matches!(e, Some(e) if e.Status().unwrap() == WiFiDirectAdvertisementPublisherStatus::Started)
        {
            println!("Hello");
            Ok(())
        } else {
            println!(
                "Advertisement: Status: {:?} Error: {:?}",
                e.Status().unwrap(),
                e.Error()
            );
            //Change for an error message later
            Ok(())
        }
    }

    fn on_socket_connection_received(sender: &Option<StreamSocketListener>, e: &Option<StreamSocketListenerConnectionReceivedEventArgs>, pending_connections: HashMap<StreamSocketListener, WiFiDirectDevice>, connected_devices: Vec<ConnectedDevice> {
        println!("Connecting to remote side on L4 layer...");
        let server_socket: StreamSocket = e.Socket();

        let wfd_device: WiFiDirectDevice = ptr::null_mut();

        let node = pending_connections.get(sender)

        if wfd_device == ptr::null_mut() {

            println!("Unexpected Connection ignorned");
            server_socket.Close();
            return;
        }

        let socket_rw: SocketReaderWriter = SocketReaderWriter::new(server_socket);
        
        // The first message sent is the name of the connection.
        let message: HSTRING = socket_rw.read_message_async().await;

        //Add this connection to the list of active connections.
        connected_devices.append(ConnectedDevice(message, wfd_device, socket_rw));

        //Keep reading messages until the socket is closed
        while (message)
        {
            message = socket_rw.read_message_async().await;
        }

    }

    async fn get_pin_from_user_async() -> HSTRING {
        unimplemented!();
    }

    async fn request_pair_device_async(pairing: DeviceInformationPairing) -> bool {
        let connection_params = WiFiDirectConnectionParameters::new();

        let device_pairing_kinds: DevicePairingKinds = DevicePairingKinds::ConfirmOnly
            | DevicePairingKinds::DisplayPin
            | DevicePairingKinds::ProvidePin;

        connection_params.PreferredPairingProcedure();

        let custom_pairing: DeviceInformationCustomPairing = pairing.Custom();

        //Could add a pin with custom_pairing requested()

        let result: DevicePairingResult = customPairing.PairAsync(
            devicePairingKinds,
            DevicePairingProtectionLevel::Default,
            connectionParams,
        );
        if (result.Status() != DevicePairingResultStatus::Paired) {
            println!("Pair Async failed, Status: {:?}", result.Status());
            return false;
        }

        return true;
    }

    async fn is_aep_paired_async(device_id: HSTRING) -> bool {
        let additional_properties: Vec<String> = Vec::new();
        additional_properties.append("System.Devices.Aep.DeviceAddress".to_string());

        let dev_info: DeviceInformation = ptr::null_mut();
            dev_info = DeviceInformation::CreateFromIdAsync(device_id, additional_properties).await;

        if (dev_info == ptr::null_mut())
        {
            println!("Device Information is null");
            return false;
        }

        let device_address: String = dev_info.Properties().Lookup("System.Devices.Aep.DeviceAddress"));
        let device_selector: String = format!("System.Devices.Aep.AepId:=\"{}\"", device_address);
        let paired_device_collection: DeviceInformationCollection  = DeviceInformation::FindAllAsync(device_selector, ptr::null_mut(), DeviceInformationKind::Device);
        return paired_device_collection.Size() > 0;
    }


    async fn handle_connection_request_async(
        connection_request: WiFiDirectConnectionRequest,
        pending_connections: HashMap<StreamSocketListener, WiFiDirectDevice>
    ) -> bool {
        let device_name: HSTRING = connection_request.DeviceInformation().Name();
        let pairing: DeviceInformationPairing = connection_request.DeviceInformation().Pairing();

        let is_paired: bool = (pairing && pairing.IsPaired())
            || (is_aep_paired_async(connection_request.DeviceInformation().Id()).await);

        if is_paired {
            println!("Connection request recieved from {:?}", deviceName);

            //ask for user input to see if true TODO

            let accept: bool = true;

            //Decline request
            if !accept {
                return false;
            }
        }

        println!("Connecting to {:?} ...", device_name);

        //pair device if not already paired

        if !is_paired {
            if (!Advertiser.request_pair_device_async(pairing).await) {
                return false;
            }
        }
        let wfd_device: WiFiDirectDevice = ptr::null_mut()

        wfd_device = WiFiDirectDevice::FromIdAsync(connection_request.DeviceInformation().Id()).await;

        // If the status of the connection is changed TODO
        // connectionStatusChangedToken

        let listener_socket: StreamSocketListener = StreamSocketListener::new();
         // This listenerSocket serves two purposes.
            // 1. It keeps the listenerSocket alive until the connection is received.
            // 2. It allows us to map the listenerSocket to the corresponding WiFiDirectDevice
            //    when the connection is received.

        pending_connections.insert(listener_socket, wfd_device);

        listener_socket.ConnectionRecieved(&TypedEventHandler::new(&Advertiser::on_socket_connection_recieved));

        let endpoint_pairs: Result<IVectorView<EndpointPair>> = wfd_device.GetConnectionEndpointPairs();

        // TODO add a global setting for the server por
        listener_socket.BindEndpointAsync(endpoint_pairs.GetAt(0).LocalHostName(), HSTRING::try_from("50001")).await;

        //error handling
        
        println!("Devices connected on L2, listening on IP Address: {:?}, Port: 50001", endpoint_pairs.GetAt(0).LocalHostName().DisplayName());

        return true;
    }
}

async fn on_connection_requested(
    sender: &Option<WiFiDirectConnectionListener>,
    e: &Option<WiFiDirectAdvertisementPublisherStatusChangedEventArgs>,
) -> windows::Result<()> {
    // body of your event handler
    let connection_request: WiFiDirectConnectionRequest = e.GetConnectionRequest();
    if (!Advertiser::handle_connection_request_async(connection_request).await) {
        println!(
            "Connection request from {:?} was declined {:?}",
            connectionRequest.DeviceInformation().Name()
        );
        connection_request.close();
    }
}

fn main() -> windows::Result<()> {
    Ok(())

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
