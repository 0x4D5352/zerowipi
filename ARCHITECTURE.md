# zerowipi architecture/design doc

## Goal

ZeroWiPi is intended to utilize the limited resources of a Raspberry Pi Zero W
to act as a passive WiFi scanner and tester. It uses Golang to minimize resource
consumption as compared with the other language I am most familiar with (Python),
while maximizing modern conveniences like garbage collection and concurrency.
The ZeroWiPi binary `zwp` will perform the following tasks:

1. Scan and enumerate available WiFi access points.
2. Attempt to connect to any available public access points.
3. Attempt to break into any available protected access points.
4. Attempt to phone home on any access point successfully connected to.
5. Conduct subnet enumeration on any access point successfully connected to.
6. Send results of 1-5 to home on an access point where task 4 was successful.

## Architecture

Each task will require its own dedicated workers, as well as additional workers
to manage database interactions and perform system administration. This will allow
the application to adjust its behavior based on resource constraints as well as
maintain persistence in the event of shutdown or other disruptions.

### Workers

1. WiFi Scanner - Infinite loop, scans for WAPs, sends results if change from prev.
2. Scan Parser - Takes results from 1, formats values, sends to DB worker.
3. DB Worker - Two subroutines: loop to handle maintenance, insert/update db table.
4. WiFi Connector - Wakes on DB changes, iterates through pub APs and tries connections.
5. WiFi Penetrator - Wakes on DB changes, iteates through priv APs and tries breaking.
6. Home Dialer - Wakes on successful 4/5, tries to GET home/health.
7. Nmapper - Wakes on successful 4/5, scans network and saves to local disk.
8. Data Worker - Wakes on 200 from Home Dialer, sends DB and Nmap results to home
9. SysAdmin - Infinite loop, checks ram/cpu/disk and conducts maintenance tasks.

### Considerations

The Raspberry Pi Zero W has the following (relevant) specifications:

- 802.11 b/g/n wireless LAN
- Bluetooth 4.1
- Bluetooth Low Energy (BLE)
- 1GHz, single-core CPU
- 512MB RAM
- ~Mini HDMI® port and micro USB On-The-Go (OTG) port~
- Micro USB power
- ~HAT-compatible 40-pin header~
- ~Composite video and reset headers~
- ~CSI camera connector~

To conserve on resources, Raspberry Pi OS Lite is used. `uname` on the pi shows
that it uses `Linux 6.12.47+rpt-rpi-v6 #1 Raspbian 1:6.12.47-1+rpt1 (2025-09-16)`
with an `armv6l` CPU architecture. At idle, the OS uses about 112MB of RAM, which
leaves me with approximately 400MB of RAM for everything that I need to do.

Running `free -m` gives the following output:

```bash
               total        used        free      shared  buff/cache   available
Mem:             427         113         221           2         143         314
Swap:            426           0         426
```

So in reality, I'm more likely to have around 300MB to work with. As a form of
insurance, I've installed an 8GB MicroSD card on my Pi Zero W, which should allow
me to take performance hits on speed in order to leverage disk space. Clever usage
of grep and/or SQLite is one possible solution, but requires additional research
to know for sure.

## MVP

At a bare minimum, Tasks 1,2, and 4 need to be functional. This would necessitate
the implementation of workers 1, 2, 3, 4, and 6. 3 could be excluded if the MVP
is scaled back to "Scan WAPs, attempt to connect, phone home when successfully
connected to a WAP"

## Dependencies

Network adapters are an operating system level interaction, so this utility will
require the following linux binaries on the host:

- nmcli (`nmcli -t -f ALL dev wifi list`)

or

- iwlist (`sudo iwlist <interface_name> scan`)
- ip addr (`ip -j addr` for json or `ip -o addr` for oneline string)

I have confirmed that the Raspberry Pi OS Lite version specified above has all
three of the specified binaries, so should be seen as stable dependencies.

### hurdles discovered

nmcli does not automatically scan, and requires `nmcli device wifi rescan` or
`nmcli dev wifi list --rescan yes` in order to poll existing results. additionally,
`nmcli device wifi rescan` requires some sort of root privilege in order to work.

to work around this issue, the following line needs to be added to the polkit rules
at `/etc/polkit-1/rules.d/10-nm-wifi-san-rules`:

```bash
polkit.addRule(function(action, subject) {
  if (action.id == "org.freedesktop.NetworkManager.wifi.scan" &&
      subject.isInGroup("netdev")) {
    return polkit.Result.YES;
  }
});
```

once done, run `sudo usermod -aG netdev "$USER"`, then run
`sudo systemctl restart polkit`

the two commands should work from this point on
