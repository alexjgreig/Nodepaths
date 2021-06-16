fn main() {
    windows::build!(
        Windows::Devices::WiFiDirect::*,
        Windows::Devices::Enumeration::*,
        Windows::Networking::*,
        Windows::Foundation::*,
        Windows::Networking::Sockets::*,
        Windows::Foundation::IAsyncAction,
        Windows::Foundation::Collections::IMapView,
        Windows::Foundation::Collections::IIterable,
        Windows::Foundation::Collections::IVector,
        Windows::Foundation::Collections::IKeyValuePair,
        Windows::Storage::Streams::*,
    );
}
