# Installation

## Windows

- Copy the `nex-dissector-plugin` folder to `%appdata%\Wireshark\plugins`.
- Create `%appdata%\Wireshark\nex-keys.txt` and (optionally) add your pid/password.

## macOS/Linux

- Copy the `nex-dissector-plugin` folder to `~/.local/lib/wireshark/plugins/` (you may need to create this folder).
- Create `~/.config/wireshark/nex-keys.txt` and (optionally) add your pid/password.

# Getting your NEX PID/password

You will need to add your NEX PID and your NEX password (for your device) in `nex-keys.txt` in the Wireshark folder - the dissector will automatically derive the needed key from the PID/password and write it back to the file. The format is `nexpid:nexpassword`.

## 3DS

Run [this homebrew application](https://9net.org/~stary/get_3ds_pid_password.3dsx) - the source code is in the `get_3ds_pid_password` folder in this repository. It will create a file `nex-keys.txt` on the root of the SD card in the correct format.

## Wii U
This assumes you have a HTTP proxy set up with your Wii U.
You can find your NEX PID and password in a request to `https://account.nintendo.net/v1/api/provider/nex_token/@me?game_server_id=xxx`. The response looks like this (formatted for clarity):

```
HTTP/1.1 200 OK
Server: Nintendo 3DS (http)
X-Nintendo-Date: xxx
Content-Type: application/xml;charset=UTF-8
Content-Length: xxx
Date: xxx

<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<nex_token>
    <host>IP</host>
    <nex_password>nexpassword</nex_password>
    <pid>nexpid</pid>
    <port>PORT</port>
    <token>token</token>
</nex_token>
</xml>
```
# What works
* Dissection of PRUDP v0 (3DS, WiiU friends)
* Dissection of PRUDP v1 (Some 3DS games, most Wii U uses)
* Automatic secure connection decryption if the connections are in the same pcap.
* Automatic generation of dissector code from wiki, including structure definitions.
* Data<> handling

# What doesn't work
* Dissection of PRUDP-Lite (Switch)
* Fragment reassembly (sometimes)

Shoutouts to Kinnay's documentation at https://github.com/Kinnay/NintendoClients, it was absolutely essential to understand any of this.
