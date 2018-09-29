# How to install?
To install the dissector, copy init.lua and the lua/ directory to %appdata%/Wireshark (or equivalent linux location at ~/.wireshark/).

This is done because the Wireshark plugin system sucks and has no way to guarantee load order.
If you already have a custom init.lua you can probably figure out how to merge them.

You will need to add your NEX PID and your NEX password (for your device) in 'nex-keys.txt' in the Wireshark folder - the dissector will automatically derive the needed key from the PID/password and write it back to the file. 

# What does it do
* Dissection of PRUDP v0 (3DS, WiiU friends)
* Automatic secure connection decryption if the connections are in the same pcap.
* Automatic generation of dissector code from wiki, including structure definitions.
* Data<> handling

# What does it not do
* Dissection of PRUDP v1 (Some 3DS games, most Wii U uses) or PRUDP-Lite (Switch)
* Fragment reassembly.
* Work reliably.

Shoutouts to Kinnay's documentation at https://github.com/Kinnay/NintendoClients, it was absolutely essential to understand any of this.
