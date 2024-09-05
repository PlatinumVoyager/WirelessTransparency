<img src="https://github.com/user-attachments/assets/b0a6d560-96e1-4b0d-90a2-472fb3c4f316">

## About
WirelessTransparency was first developed with the idea of understanding the IEEE 802.11 protocol to a further lower-level extent. As such this repository of files is close to a year old and development has been halted since mid January, with development initially beginning in late December. This project has been released as open source with the intentions of providing more context and information on the basis of how such tool are usually structured/created.

## Build
* `git clone https://github.com/PlatinumVoyager/WirelessTransparency.git && cd WirelessTransparency ; mkdir bin && make build`

## Execution
* `sudo -E ./bin/WIRELESSTRANSPARENCY <interface>`

## Info
This version of _WIRELESSTRANSPARENCY_ uses the older `iwconfig` command to change the state of the wireless network adapter to "monitor mode".

Ideally it would be suitable to call: `sudo iw dev <interface> interface add <name> type monitor` where `<name>` is the NIC descriptor used in conjunction when calling `sudo -E ./bin/WIRELESSTRANSPARENCY <interface>`

_NOTE:_ WIRELESSTRANSPARENCY will set the state (Up/Down) of the NIC through IOCTL calls to a local UDP socket.

## Details

Generic startup view run with the following command: `sudo ifconfig mon0 down && sudo macchanger -r mon0 ; sudo ifconfig mon0 up && sudo -E ./bin/WIRELESSTRANSPARENCY mon0`

_NOTE:_ The NIC was brought down (2 times in total) in order to change the Media Access Control address of the device in use. By default WT does not provide an application process to facilitate the change/modification of MAC addresses.

<img src="https://github.com/user-attachments/assets/6cae6ed5-6d92-4a22-b0d7-8dd1951b97b1">


* Press `<ENTER>` to view your wireless surroundings.

  ## Expected View
  _Intentially redacted.....except for that one Calix device_

  <img src="https://github.com/user-attachments/assets/68e45b77-662b-44c5-975d-f37bb80ddade">
