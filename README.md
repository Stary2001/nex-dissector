# How to install?

If you have an existing `init.lua` file to load Wireshark plugins in your desired order, merge it with the `init.lua` from this repository.

You will need to add your NEX PID and your NEX password (for your device) in `nex-keys.txt` in the Wireshark folder - the dissector will automatically derive the needed key from the PID/password and write it back to the file. The format is `nexpid:nexpassword`.

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

Each game 

## Windows

- Copy `init.lua` to `%appdata%\Wireshark\plugins`
- Create the directory `%appdata%\Wireshark\lua`
- Symlink the `nex` directory to the `nex` directory in this repository (run from elevated command prompt):
  ```
  cd %appdata%\Wireshark\lua
  mklink /d nex C:\projects\nex-dissector\lua\nex
  ```
- Create `%appdata%\Wireshark\nex-keys.txt` and (optionally) add your pid/password.

## OSX

- Copy `init.lua` to `~/.config/wireshark`
- Create the directory `~/.config/wireshark/lua`
- Symlink the `nex` directory to the `nex` directory in this repository:
  ```
  cd ~/.config/wireshark/lua
  ln -s ~/projects/nex-dissector/lua/nex nex
  ```
- Create `~/.config/wireshark/nex-keys.txt` and (optionally) add your pid/password.

# What does it do
* Dissection of PRUDP v0 (3DS, WiiU friends)
* Dissection of PRUDP v1 (Some 3DS games, most Wii U uses)
* Automatic secure connection decryption if the connections are in the same pcap.
* Automatic generation of dissector code from wiki, including structure definitions.
* Data<> handling

# What does it not do
* Dissection of PRUDP-Lite (Switch)
* Fragment reassembly.
* Work reliably.

Shoutouts to Kinnay's documentation at https://github.com/Kinnay/NintendoClients, it was absolutely essential to understand any of this.
