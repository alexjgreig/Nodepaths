fn main() {
    windows::build!(
        Windows::Devices::WiFiDirect::*,
        Windows::Devices::Enumeration::*,
        Windows::Networking::Sockets::*,
        Windows::Foundation::*,
        Windows::Storage::Streams::*,
    );
}
