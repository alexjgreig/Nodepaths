use crate::cryptography::{PublicKey, SecretKey, SharedSecret};
use crate::socket_reader_writer::SocketReaderWriter;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io;
use std::io::{Read, Write};

use bindings::CreateIVectorWRC::CreateIVector;
use bindings::Windows::Devices::Enumeration::DeviceInformation;
use bindings::Windows::Devices::Enumeration::DeviceInformationCollection;
use bindings::Windows::Devices::Enumeration::DeviceInformationCustomPairing;
use bindings::Windows::Devices::Enumeration::DeviceInformationPairing;
use bindings::Windows::Devices::Enumeration::DevicePairingKinds;
use bindings::Windows::Devices::Enumeration::DevicePairingProtectionLevel;
use bindings::Windows::Devices::Enumeration::DevicePairingResult;
use bindings::Windows::Devices::Enumeration::DevicePairingResultStatus;
use bindings::Windows::Devices::Enumeration::DeviceWatcher;
use bindings::Windows::Devices::Enumeration::*;
use bindings::Windows::Devices::WiFiDirect::WiFiDirectAdvertisementListenStateDiscoverability;
use bindings::Windows::Devices::WiFiDirect::WiFiDirectAdvertisementPublisher;
use bindings::Windows::Devices::WiFiDirect::WiFiDirectAdvertisementPublisherStatus;
use bindings::Windows::Devices::WiFiDirect::WiFiDirectAdvertisementPublisherStatusChangedEventArgs;
use bindings::Windows::Devices::WiFiDirect::WiFiDirectConnectionListener;
use bindings::Windows::Devices::WiFiDirect::WiFiDirectConnectionParameters;
use bindings::Windows::Devices::WiFiDirect::WiFiDirectConnectionRequest;
use bindings::Windows::Devices::WiFiDirect::WiFiDirectConnectionRequestedEventArgs;
use bindings::Windows::Devices::WiFiDirect::WiFiDirectDevice;
use bindings::Windows::Devices::WiFiDirect::WiFiDirectDeviceSelectorType;
use bindings::Windows::Devices::WiFiDirect::WiFiDirectInformationElement;
use bindings::Windows::Foundation::Collections::IIterable;
use bindings::Windows::Foundation::Collections::IIterator;
use bindings::Windows::Foundation::Collections::IVector;
use bindings::Windows::Foundation::Collections::IVectorView;
use bindings::Windows::Foundation::EventRegistrationToken;
use bindings::Windows::Foundation::*;
use bindings::Windows::Networking::EndpointPair;
use bindings::Windows::Networking::Sockets::StreamSocket;
use bindings::Windows::Networking::Sockets::StreamSocketListener;
use bindings::Windows::Networking::Sockets::StreamSocketListenerConnectionReceivedEventArgs;
use bindings::Windows::Networking::Sockets::*;
use bindings::Windows::Storage::Streams::ByteOrder;
use bindings::Windows::Storage::Streams::UnicodeEncoding;

use windows::IInspectable;
use windows::HSTRING;

use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::mem;
use std::ptr;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use rand::prelude::*;

use futures::executor::block_on;
use futures::future::Future;

use tokio::runtime::Runtime;
use tokio::sync::mpsc;

#[derive(Clone)]
struct ConnectedDevice {
    display_name_in: HSTRING,
    wfd_device_in: Arc<WiFiDirectDevice>,
    socket_rw_in: SocketReaderWriter,
}

impl ConnectedDevice {
    fn new(
        display_name_in: HSTRING,
        wfd_device_in: Arc<WiFiDirectDevice>,
        socket_rw_in: SocketReaderWriter,
    ) -> Self {
        Self {
            display_name_in,
            wfd_device_in,
            socket_rw_in,
        }
    }
}

#[derive(Clone)]
struct DiscoveredDevice {
    device_info: DeviceInformation,
}

impl DiscoveredDevice {
    fn new(device_info: DeviceInformation) -> Self {
        DiscoveredDevice { device_info }
    }
    /*
    fn display_name (&self) -> String {
        &self.device_info.Name().unwarp().
    }
    */
}
enum AdvertiserEvent {
    Publisher(
        Option<WiFiDirectAdvertisementPublisher>,
        Option<WiFiDirectAdvertisementPublisherStatusChangedEventArgs>,
    ),
    Listener(
        Option<WiFiDirectConnectionListener>,
        Option<WiFiDirectConnectionRequestedEventArgs>,
    ),
}

enum ConnectorEvent {
    Added(Option<DeviceInformation>),
    EnumerationCompleted,
    Stopped,
}

pub struct Node {
    publisher: WiFiDirectAdvertisementPublisher,
    listener: Option<WiFiDirectConnectionListener>,
    device_watcher: Option<DeviceWatcher>,
    information_elements: Vec<WiFiDirectInformationElement>,
    connected_devices: Arc<Mutex<Vec<ConnectedDevice>>>,
    discovered_devices: Arc<Mutex<Vec<DiscoveredDevice>>>,
    status_changed_token: Option<EventRegistrationToken>,
    connection_requested_token: Option<EventRegistrationToken>,
    watcher_added_token: Option<EventRegistrationToken>,
    pub config: Config,
}

impl Node {
    pub async fn new(advertiser: bool) -> Self {
        //LISTENER
        //TODO: Take in user input to see if they want to connect or broadcast
        let str_server_port = "50001";
        let information_elements: Vec<WiFiDirectInformationElement> = Vec::new();

        let config = Config::load_config();

        let publisher: WiFiDirectAdvertisementPublisher =
            WiFiDirectAdvertisementPublisher::new().unwrap();

        let mut connected_devices: Arc<Mutex<Vec<ConnectedDevice>>> =
            Arc::new(Mutex::new(Vec::new()));

        let mut discovered_devices: Arc<Mutex<Vec<DiscoveredDevice>>> =
            Arc::new(Mutex::new(Vec::new()));

        if advertiser {
            /*
            let status_changed_token = tokio::spawn( async { tx.send(publisher
                .StatusChanged(&TypedEventHandler::new(Node::on_status_changed))
                .unwrap()).await());
            */

            let listener: WiFiDirectConnectionListener =
                WiFiDirectConnectionListener::new().unwrap();

            let connected_devices_c = Arc::clone(&connected_devices);

            let (tx, mut rx) = mpsc::channel(10);
            let tx2 = tx.clone();

            let handler = tokio::spawn(async move {
                println!("Event Handler Started");
                while let Some(event) = rx.recv().await {
                    match event {
                        AdvertiserEvent::Publisher(sender, args) => {
                            println!("handling publisher event");
                            Node::on_status_changed(&sender, &args).unwrap();
                        }
                        AdvertiserEvent::Listener(sender, args) => {
                            println!("handling listener event");
                            Node::on_connection_requested(
                                &sender,
                                &args,
                                Arc::clone(&connected_devices_c),
                            );
                        }
                    }
                }
            });

            /*
            BarEventHandler::new(|| {
                tx.blocking_send(Event::Bar);
            });

            */
            let status_changed_token =
                publisher
                    .StatusChanged(&TypedEventHandler::new(
                        move |sender: &Option<WiFiDirectAdvertisementPublisher>,
                              args: &Option<
                            WiFiDirectAdvertisementPublisherStatusChangedEventArgs,
                        >| {
                            let (sender, args) = (sender.clone(), args.clone());
                            tx.blocking_send(AdvertiserEvent::Publisher(sender, args));
                            Ok(())
                        },
                    ))
                    .unwrap();

            let connection_requested_token = listener
            .ConnectionRequested(&TypedEventHandler::new(
                move |sender: &Option<WiFiDirectConnectionListener>,
                      args: &Option<WiFiDirectConnectionRequestedEventArgs>| {
                    let (sender, args) = (sender.clone(), args.clone());
                    tx2.blocking_send(AdvertiserEvent::Listener(sender, args));
                    Ok(())
                },
            ))
            .unwrap();

            handler.await.unwrap();

            let discoverability = WiFiDirectAdvertisementListenStateDiscoverability::Intensive;
            publisher
                .Advertisement()
                .unwrap()
                .SetListenStateDiscoverability(discoverability);

            publisher
                .Advertisement()
                .unwrap()
                .InformationElements()
                .unwrap()
                .Clear();
            Node {
                publisher: publisher,
                listener: Some(listener),
                device_watcher: None,
                information_elements: information_elements,
                connected_devices: Arc::clone(&connected_devices),
                discovered_devices: Arc::clone(&discovered_devices),
                status_changed_token: Some(status_changed_token),
                connection_requested_token: Some(connection_requested_token),
                watcher_added_token: None,
                config: config,
            }
        } else {
            publisher.Start();
            if (publisher.Status().unwrap() == WiFiDirectAdvertisementPublisherStatus::Started) {
                println!("Advertisment Started.");
            } else {
                println!("Advertisment Failed: Code {:?}", publisher.Status());
            }

            println!("Finding Devices...");
            /*
            let device_selector: HSTRING =
                WiFiDirectDevice::GetDeviceSelector2(WiFiDirectDeviceSelectorType::DeviceInterface)
                    .unwrap();

             let additional_properties: IVector<HSTRING> = CreateIVector::CreateVector().unwrap();

            additional_properties
                .InsertAt(
                    0,
                    "System.Devices.WiFiDirect.InformationElements".to_string(),
                )
                .unwrap();
            */
            let device_selector: HSTRING = WiFiDirectDevice::GetDeviceSelector().unwrap();

            let device_watcher: DeviceWatcher =
                DeviceInformation::CreateWatcherAqsFilter(device_selector).unwrap();

            let mut discovered_devices_c = Arc::clone(&discovered_devices);

            let (tx, mut rx) = mpsc::channel(10);
            let tx2 = tx.clone();
            let tx3 = tx.clone();

            let handler = tokio::spawn(async move {
                println!("Event Handler Started");
                while let Some(event) = rx.recv().await {
                    match event {
                        ConnectorEvent::Added(device_info) => {
                            println!("{:?}", device_info.unwrap().Name().unwrap());
                            /*
                            Arc::clone(&discovered_devices_c)
                                .lock()
                                .unwrap()
                                .push(DiscoveredDevice::new(device_info.unwrap()));
                            */
                        }
                        ConnectorEvent::EnumerationCompleted => {
                            println!("Device Watcher Enumeration Completed")
                        }
                        ConnectorEvent::Stopped => println!("Device Watcher Stopped"),
                    }
                }
            });

            let watcher_added_token = device_watcher
                .Added(&TypedEventHandler::new(
                    move |device_watcher: &Option<DeviceWatcher>,
                          device_info: &Option<DeviceInformation>| {
                        let device_info = device_info.clone();
                        tx.blocking_send(ConnectorEvent::Added(device_info));
                        Ok(())
                    },
                ))
                .unwrap();
            let watcher_enumeration_completed_token = device_watcher
                .EnumerationCompleted(&TypedEventHandler::new(
                    move |device_watcher: &Option<DeviceWatcher>,
                          device_info: &Option<IInspectable>| {
                        tx2.blocking_send(ConnectorEvent::EnumerationCompleted);
                        Ok(())
                    },
                ))
                .unwrap();
            let watcher_stopped_token = device_watcher
                .Stopped(&TypedEventHandler::new(
                    move |device_watcher: &Option<DeviceWatcher>,
                          device_info: &Option<IInspectable>| {
                        tx3.blocking_send(ConnectorEvent::Stopped);
                        Ok(())
                    },
                ))
                .unwrap();

            device_watcher.Start().unwrap();

            handler.await.unwrap();
            Node {
                publisher: publisher,
                listener: None,
                device_watcher: Some(device_watcher),
                information_elements: information_elements,
                connected_devices: Arc::clone(&connected_devices),
                discovered_devices: Arc::clone(&discovered_devices),
                status_changed_token: None,
                connection_requested_token: None,
                watcher_added_token: Some(watcher_added_token),
                config: config,
            }
        }
    }

    fn stop(&mut self, advertiser: bool) {
        &self.publisher.Stop();
        if advertiser {
            &self
                .publisher
                .RemoveStatusChanged(&self.status_changed_token.unwrap());
            &self
                .listener
                .as_ref()
                .unwrap()
                .RemoveConnectionRequested(&self.connection_requested_token.unwrap());

            &self.information_elements.clear();
            println!("Advertisment Stopped Successfully")
        } else {
            &self
                .device_watcher
                .as_ref()
                .unwrap()
                .RemoveAdded(&self.watcher_added_token.unwrap());
            &self.device_watcher.as_ref().unwrap().Stop();
            println!("Device Watcher Stopped");
        }
    }
    fn on_status_changed(
        sender: &Option<WiFiDirectAdvertisementPublisher>,
        e: &Option<WiFiDirectAdvertisementPublisherStatusChangedEventArgs>,
    ) -> Result<(), windows::Error> {
        // body of your event handler
        if matches!(e, Some(e) if e.Status().unwrap() == WiFiDirectAdvertisementPublisherStatus::Started)
        {
            println!("Status Change");
            Ok(())
        } else {
            println!(
                "Advertisement: Status: {:?} Error: {:?}",
                e.as_ref().unwrap().Status().unwrap(),
                e.as_ref().unwrap().Error()
            );
            //Change for an error message later
            Ok(())
        }
    }

    async fn on_socket_connection_received(
        sender: &Option<StreamSocketListener>,
        e: &Option<StreamSocketListenerConnectionReceivedEventArgs>,
        wfd_device: Arc<WiFiDirectDevice>,
        connected_devices: Arc<Mutex<Vec<ConnectedDevice>>>,
    ) -> Result<(), windows::Error> {
        println!("Connecting to remote side on L4 layer...");
        let server_socket: StreamSocket = e.as_ref().unwrap().Socket().unwrap();

        let socket_rw: SocketReaderWriter = SocketReaderWriter::new(server_socket);

        // The first message sent is the name of the connection.
        let mut message: HSTRING = socket_rw.read_message_async().await;

        //Add this connection to the list of active connections.
        let mut connected_devices = connected_devices.lock().unwrap();
        connected_devices.push(ConnectedDevice {
            display_name_in: message.clone(),
            wfd_device_in: wfd_device,
            socket_rw_in: socket_rw,
        });

        //Keep reading messages until the socket is closed
        while (!&message.is_empty()) {
            message = connected_devices
                .last()
                .unwrap()
                .socket_rw_in
                .read_message_async()
                .await;
        }
        Ok(())
    }

    async fn handle_connection_request_async(
        connection_request: &WiFiDirectConnectionRequest,
        connected_devices: Arc<Mutex<Vec<ConnectedDevice>>>,
    ) -> bool {
        let device_name: HSTRING = connection_request
            .DeviceInformation()
            .unwrap()
            .Name()
            .unwrap();
        let pairing: DeviceInformationPairing = connection_request
            .DeviceInformation()
            .unwrap()
            .Pairing()
            .unwrap();

        println!("Connection request recieved from {:?}", device_name);

        //ask for user input to see if true TODO

        let accept: bool = true;

        //Decline request
        if !accept {
            return false;
        }

        println!("Connecting to {:?} ...", device_name);

        //pair device if not already paired

        // Node::request_pair_device_async(pairing).await;

        let wfd_device: Arc<WiFiDirectDevice> = Arc::new(
            WiFiDirectDevice::FromIdAsync(
                connection_request
                    .DeviceInformation()
                    .unwrap()
                    .Id()
                    .unwrap(),
            )
            .unwrap()
            .await
            .unwrap(),
        );

        // If the status of the connection is changed TODO
        // connectionStatusChangedToken

        let listener_socket: StreamSocketListener = StreamSocketListener::new().unwrap();
        // This listenerSocket serves two purposes.
        // 1. It keeps the listenerSocket alive until the connection is received.
        // 2. It allows us to map the listenerSocket to the corresponding WiFiDirectDevice
        //    when the connection is received.
        //
        let wfd_device_c = Arc::clone(&wfd_device);
        listener_socket
            .ConnectionReceived(TypedEventHandler::new(
                move |sender: &Option<StreamSocketListener>,
                 args: &Option<StreamSocketListenerConnectionReceivedEventArgs>| {
                    let (sender, args) = (sender.clone(), args.clone());
                    block_on(Node::on_socket_connection_received(
                        &sender,
                        &args,
                        Arc::clone(&wfd_device_c),
                        Arc::clone(&connected_devices),
                    ))
                    //TODO Add error handling with Result by add windows result to handler functions
                },
            ))
            .unwrap();

        let endpoint_pairs: IVectorView<EndpointPair> = Arc::clone(&wfd_device)
            .GetConnectionEndpointPairs()
            .unwrap();

        // TODO add a global setting for the server por
        listener_socket
            .BindEndpointAsync(
                endpoint_pairs.GetAt(0).unwrap().LocalHostName().unwrap(),
                HSTRING::try_from("50001".to_string()).unwrap(),
            )
            .unwrap()
            .await;

        //error handling

        println!(
            "Devices connected on L2, listening on IP Address: {:?}, Port: 50001",
            endpoint_pairs
                .GetAt(0)
                .unwrap()
                .LocalHostName()
                .unwrap()
                .DisplayName()
        );

        return true;
    }

    async fn on_connection_requested(
        sender: &Option<WiFiDirectConnectionListener>,
        e: &Option<WiFiDirectConnectionRequestedEventArgs>,
        connected_devices: Arc<Mutex<Vec<ConnectedDevice>>>,
    ) -> Result<(), windows::Error> {
        // body of event handler
        let connection_request: WiFiDirectConnectionRequest =
            e.as_ref().unwrap().GetConnectionRequest().unwrap();
        if (!Node::handle_connection_request_async(&connection_request, connected_devices).await) {
            println!(
                "Connection request from {:?} was declined",
                &connection_request.DeviceInformation().unwrap().Name()
            );
            connection_request.Close();
        }
        Ok(())
    }

    pub async fn send_message(&self, message: HSTRING) {
        // TODO add the ability if user has multiple connections to select the connection
        let connected_device = &self.connected_devices.lock().unwrap()[0];
        connected_device
            .socket_rw_in
            .write_message_async(message)
            .await;
    }

    async fn connect(&self) {
        let discovered_device = &self.discovered_devices.lock().unwrap()[0];
        let device_info = discovered_device.clone().device_info;

        println!("Connecting to {:?} ...", device_info.Name().unwrap());

        let wfd_device: Arc<WiFiDirectDevice> = Arc::new(
            WiFiDirectDevice::FromIdAsync(device_info.Id().unwrap())
                .unwrap()
                .await
                .unwrap(),
        );

        let endpoint_pairs: IVectorView<EndpointPair> = Arc::clone(&wfd_device)
            .GetConnectionEndpointPairs()
            .unwrap();

        let remote_host_name = endpoint_pairs.GetAt(0).unwrap().RemoteHostName().unwrap();
        // TODO add a global setting for the server por
        //error handling

        println!(
            "Devices connected on L2, listening on IP Address: {:?}, Port: 50001",
            &remote_host_name
        );

        thread::sleep(Duration::from_millis(2000));

        println!("Connecting to remote side on L4 layer...");

        let client_socket: StreamSocket = StreamSocket::new().unwrap();

        client_socket
            .ConnectAsync(remote_host_name, "50001".to_string())
            .unwrap()
            .await;

        let socket_rw: SocketReaderWriter = SocketReaderWriter::new(client_socket);

        let mut rng = rand::thread_rng();
        let rand: u64 = rng.gen_range(1..99999999999);
        let session_id: HSTRING =
            HSTRING::try_from(format!("Session: {}", rand.to_string())).unwrap();

        let mut connected_devices = self.connected_devices.lock().unwrap();

        connected_devices.push(ConnectedDevice::new(
            session_id.clone(),
            wfd_device,
            socket_rw,
        ));

        connected_devices
            .last()
            .unwrap()
            .socket_rw_in
            .write_message_async(session_id.clone())
            .await;
        connected_devices
            .last()
            .unwrap()
            .socket_rw_in
            .write_message_async(session_id.clone())
            .await;

        while (!connected_devices
            .last()
            .unwrap()
            .socket_rw_in
            .read_message_async()
            .await
            .is_empty())
        {
            // keep reading messages
        }
    }

    /*
    async fn get_pin_from_user_async() -> HSTRING {
        unimplemented!();
    }

    //Advanced Pairing


    async fn request_pair_device_async(pairing: DeviceInformationPairing) -> bool {
        let connection_params = WiFiDirectConnectionParameters::new().unwrap();

        let device_pairing_kinds: DevicePairingKinds = DevicePairingKinds::ConfirmOnly
            | DevicePairingKinds::DisplayPin
            | DevicePairingKinds::ProvidePin;

        connection_params.PreferredPairingProcedure();

        let custom_pairing: DeviceInformationCustomPairing = pairing.Custom().unwrap();

        //Could add a pin with custom_pairing requested()

        let result: DevicePairingResult = custom_pairing
            .PairWithProtectionLevelAndSettingsAsync(
                device_pairing_kinds,
                DevicePairingProtectionLevel::Default,
                connection_params,
            )
            .unwrap()
            .GetResults()
            .unwrap();

        if (result.Status().unwrap() != DevicePairingResultStatus::Paired) {
            println!("Pair Async failed, Status: {:?}", result.Status());
            return false;
        }

        return true;
    }
    */

    /*
    Advanced Pairing Parameters
    async fn is_aep_paired_async(device_id: HSTRING) -> bool {
        let dev_info = DeviceInformation::CreateFromIdAsyncAdditionalProperties(
            device_id,
            vec!["System.Devices.Aep.DeviceAddress".to_string()],
        )
        .unwrap()
        .await;

        match dev_info {
            Ok(dev_info) => {
                let device_address: HSTRING = HSTRING::try_from(
                    dev_info
                        .Properties()
                        .unwrap()
                        .Lookup("System.Devices.Aep.DeviceAddress")
                        .unwrap(),
                )
                .unwrap();
                let device_selector: String =
                    format!("System.Devices.Aep.AepId:=\"{}\"", device_address);
                let paired_device_collection: DeviceInformationCollection =
                    DeviceInformation::FindAllAsyncAqsFilterAndAdditionalProperties(
                        device_selector,
                        DeviceInformationKind::Device.try_into().unwrap(),
                    )
                    .unwrap()
                    .await
                    .unwrap();
                return paired_device_collection.Size().unwrap() > 0;
            }

            Err(e) => {
                println!("Device Information is null {}", e);
                return false;
            }
        }
    }
    */
}

//TODO: MOVE ADVERTISER INTO SEPARATE FILE, Possibly make it the node and have a generic structure.

#[derive(Serialize, Deserialize)]
pub struct Keys {
    pub secret_key: [u8; 32],
    pub public_key: [u8; 32],
}

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub username: String,
    pub keys: Keys,
}

impl Config {
    pub fn load_config() -> Self {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open("src/config.toml")
            .expect("Couldn't open config file.");

        let mut contents = String::new();

        file.read_to_string(&mut contents).unwrap();
        let config: Config = match toml::from_str(&contents) {
            Err(_) => create_config(),
            Ok(config) => config,
        };

        return config;
    }

    pub fn create_shared_secret(&self, their_public: &PublicKey) -> SharedSecret {
        return SecretKey::from(self.keys.secret_key).diffie_hellman(their_public);
    }
}
pub fn create_config() -> Config {
    let config = Config {
        username: get_username(),
        keys: create_ecc_keys(),
    };

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .open("src/config.toml")
        .expect("Couldn't create TOML file.");
    file.write(
        toml::Value::try_from(&config)
            .unwrap()
            .to_string()
            .as_bytes(),
    );

    return config;
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
