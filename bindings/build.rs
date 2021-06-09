fn main() {
    windows::build!(
    Windows::Win32::NetworkManagement::WiFi::*,
    Windows::Win32::System::SystemServices::HANDLE,
    );
}
