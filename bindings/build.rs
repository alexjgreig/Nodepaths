use std::process::Command;
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
        CreateIVectorWRC::CreateIVector,
    );
    //
    let mut rc =
        Command::new("C:\\Program Files (x86)\\Windows Kits\\10\\bin\\10.0.19041.0\\x64\\rc.exe")
            .arg("/r")
            .arg("/fo")
            .arg(".\\resources.lib")
            .arg(".\\nodepaths.rc2")
            .spawn()
            .expect("Failed to spawn resource compiler");
    let ecode = rc.wait().expect("Failed to wait on resource compiler");

    assert!(ecode.success(), "Resource compiler failed");

    println!("cargo:rustc-link-lib=resources");
    println!("cargo:rustc-link-search=native=C:\\Users\\Alex\\OneDrive - St Augustines College\\2021\\Software Design & Development\\Task 2\\nodepaths\\bindings");
}
