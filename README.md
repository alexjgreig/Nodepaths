# Nodepaths
A distributed communication application built upon a wireless ad-hoc network using mesh topology, made with the Rust programming language. This is a Software Design and Development project; the reason why the design documentation is included.

To run this project, clone the repository onto two devices that have wifi direct capabilities. Then locate, in the root folder, an executable called `nodepaths.exe`. Run this and there will be a menu that appears. One device will need to be the advertiser and one device will need to be the connector.

Currently, the application connects two computers together using WiFi Direct and allows them to send messages between the computers. Unfortunately, due to time concerns I did *not* implement mesh topology for interconnected nodes and the encryption and network modules have remained separate but can easily be unified. 

Thanks,
Alex.
