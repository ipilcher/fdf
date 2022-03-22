# IP Set Filter (`ipset.so`)

&copy; 2022 Ian Pilcher <<arequipeno@gmail.com>>

* [**Introduction**](#introduction)
* [**IP Sets**](#ip-sets)
  * [Creating a Set](#creating-a-set)
  * [Persisting a Set](#persisting-a-set)
  * [Using a Set](#using-a-set)
* [**Using the Filter**](#using-the-filter)

## Introduction

Most network discovery protocols feature an initial discovery message, sent via
IPv4 broadcast or IP multicast, to which "discoverees" respond with a direct
unicast answer.  When the discovery message was forwarded from a different
network, the answers must be routed to that network if they are to reach the
"discoverer." A stateful firewill will often reject (or drop) such packets,
because there is no apparent relationship between the discovery message and the
answers.

Consider the discovery protocol used by
[SiliconDust](https://www.silicondust.com/) HDHomeRun television tuners.  The
discoverer (such as the
[HDHomeRun](https://play.google.com/store/apps/details?id=com.silicondust.view)
app for Android) sends a UDP discovery
message from a randomly selected source port to the IPv4 broadcast address
(`255.255.255.255`), destination port `65001`.  An HDHomeRun tuner that receives
this discovery packet will send a unicast response from source port `65001` to
the address (IPv4 address and UDP port) from which the discovery packet
originated.  I.e., the source address of the discovery packet becomes the
destination address of the response.

Assume that one or more HDHomeRun tuners is connected to a home's "IOT" network
(`172.31.252.0/24`) and several Android TV-powered devices are connected to the
untrusted Wi-Fi network (`172.31.253.0/24`).  FDF is configured to forward
HDHomeRun discovery packets from the untrusted network to the IOT network, so
that the HDHomeRun app running on the Android TV devices can connect to the
tuner.  Routing between the networks is provided by a Linux-based system with an
`iptables` firewall (where the FDF daemon is also running).

The firewall is configured to block outbound connections from the IOT network,
so a new rule is required to allow HDHomeRun responses (which the firewall sees
as new connections) to be routed to the untrusted network.

```
Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
	︙
    0     0 ACCEPT     udp  --  *      *       172.31.252.0/24      172.31.253.0/24      udp spt:65001 state NEW
	︙
```

> **NOTE:** This rule allows HDHomeRun responses from any address on the IOT
> network.  HDHomeRun tuners do not support static IP address configuration, so
> the rule can't be made more specific unless DHCP reservations are used to set
> the addresses of the tuner(s).

This allows anything on the IOT network to send UDP traffic from port `65001` to
the untrusted network.  And because the sender controls the source port, it
effectively allows anything connected to the IOT network to send UDP traffic to
any address and port on the untrusted network.  Fortunately, this shouldn't be
an issue, because that network is already considered to be untrusted.

SiliconDust provides both command-line and GUI utilities to configure and
HDHomeRun tuners.  The utilities need to run on a workstation that is connected
to the home's trusted network (`172.31.250.0/24`).  FDF can be configured to
forward HDHomeRun discovery packets from the trusted network to the IOT network,
and an `iptables` rule can be added that allows the responses to be routed.

```
Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
	︙
    0     0 ACCEPT     udp  --  *      *       172.31.252.0/24      172.31.253.0/24      udp spt:65001 state NEW
    0     0 ACCEPT     udp  --  *      *       172.31.252.0/24      172.31.250.0/24      udp spt:65001 state NEW
	︙
```

Now anything connected to the IOT network can send UDP traffic to any
destination on the trusted network.  This isn't likely to be a serious problem
by itself, but it is the type of opening that can be part of a larger exploit.
Furthermore, it's just inelegant; the system as a whole has all of the
information required to be more intelligent about when and where to route these
response packets, so why can't it do so?

The IP set "filter," in combination with the appropriate firewall configuration,
can enable this intelligence.

> **NOTE:** "Filter" is quoted above, because the IP set filter module does not
> actually filter traffic.  Its only purpose is to add entries to an IP set,
> based on the source IP address and port of the packets that it processes.

## IP Sets

[IP sets](https://www.netfilter.org/projects/ipset/index.html) have been part of
the Linux kernel since the 2.4 series.  They are in-kernel sets of tuples of
network-related data &mdash; IP addresses, UDP or TCP ports, MAC addresses,
network addresses, etc.  See [`ipset(8)`](https://linux.die.net/man/8/ipset) for
the various types of sets that are available.

IP sets can be referenced from `iptables` rules, so packets can be accepted,
dropped, rejected, etc., based on whether their address, port, etc. is present
in a set.

### Creating a Set

The IP set filter requires sets of the `hash:ip,port` type, with timeout support
enabled.  To create a compatible set:

```
# ipset create HDHR_CLIENTS hash:ip,port timeout 0 hashsize 64
```

> **NOTES:**
>
> * `timeout 0` sets the default timeout of set entries to zero, which
>   means that entries will not be automatically removed from the set.  The set
>   default doesn't matter, because the IP set filter will set explicitly the
>   timeout value of each entry that it adds, but some timeout value must be
>   specified in order to create a set with timeout support.
>
> * `hashsize 64` creates a set with the smallest possible initial memory
>   footprint.  The kernel will automatically expand the set if its initial size
>   is inadequate, and `64` will almost certainly be adequate for any home
>   network, so this is the recommended size.

Once created, the set can be displayed.

```
# ipset list HDHR_CLIENTS
Name: HDHR_CLIENTS
Type: hash:ip,port
Revision: 6
Header: family inet hashsize 64 maxelem 65536 timeout 0 bucketsize 12 initval 0x49b44be1
Size in memory: 200
References: 0
Number of entries: 0
Members:
```

An entry can be added.  (Note that the port includes the IP protocol, not just
the port number.)  It will be automatically removed after 30 seconds.

```
# ipset add HDHR_CLIENTS 192.168.1.1,udp:65001 timeout 30

# ipset list HDHR_CLIENTS
Name: HDHR_CLIENTS
Type: hash:ip,port
Revision: 6
Header: family inet hashsize 64 maxelem 65536 timeout 0 bucketsize 12 initval 0x49b44be1
Size in memory: 264
References: 0
Number of entries: 1
Members:
192.168.1.1,udp:65001 timeout 26

# sleep 30

# ipset list HDHR_CLIENTS
Name: HDHR_CLIENTS
Type: hash:ip,port
Revision: 6
Header: family inet hashsize 64 maxelem 65536 timeout 0 bucketsize 12 initval 0x49b44be1
Size in memory: 264
References: 0
Number of entries: 0
Members:
```

### Persisting a Set

IP sets are not automatically persisted across reboots; they must be recreated
at each boot.  This repository includes a `systemd` unit file (`ipset@.service`)
that can be used to create any required IP sets at boot time.  For example, the
set above can be automatically created every time the system boots by performing
the following steps.

Create a configuration file, `/etc/sysconfig/ipset-HDHR_CLIENTS`, with the
following contents:

```
TYPE = hash:ip,port
FAMILY = inet
OPTIONS = hashsize 64 timeout 0
```

Copy the unit file to `/etc/systemd/system/` and make `systemd` aware of it.

```
# cp systemd/ipset@.service /etc/systemd/system/

# systemctl daemon-reload
```

Enable the unit and start it, if necessary.

```
# systemctl enable ipset@HDHR_CLIENTS --now
Created symlink /etc/systemd/system/multi-user.target.wants/ipset@HDHR_CLIENTS.service → /etc/systemd/system/ipset@.service.
```

Check its status.

```
# systemctl status ipset@HDHR_CLIENTS
● ipset@HDHR_CLIENTS.service - IP set - HDHR_CLIENTS
     Loaded: loaded (/etc/systemd/system/ipset@.service; enabled; vendor preset: disabled)
     Active: active (exited) since Tue 2022-03-15 18:19:32 CDT; 1min 43s ago
    Process: 710909 ExecStart=/usr/sbin/ipset -exist create HDHR_CLIENTS $TYPE family $FAMILY $OPTIONS (code=exited, status=>
   Main PID: 710909 (code=exited, status=0/SUCCESS)
        CPU: 3ms

Mar 15 18:19:32 ian.penurio.us systemd[1]: Starting IP set - HDHR_CLIENTS...
Mar 15 18:19:32 ian.penurio.us systemd[1]: Finished IP set - HDHR_CLIENTS.
```

The set can also be destroyed (`systemctl stop`) or destroyed and recreated
(`systemctl restart`).

### Using a Set

With the set in place, it can used in an `iptables` rule.  (Again assuming that
the address(es) of the HDHomeRun tuner(s) aren't known.)

```
Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
	︙
    0     0 ACCEPT     udp  --  *      *       172.31.252.0/24      172.31.250.0/24      udp spt:65001 state NEW match-set HDHR_CLIENTS dst,dst
	︙
```

> **NOTES:**
>
> * The `match-set` option is provided by the `set` module.
>
> * The `dst,dst` flags correspond to the data types in the set entries.  The
>   set type is `hash:ip,set`, so `dst,dst` means that the rule will match only
>   if the set contains an entry that matches the **destination** IP address and
>   **destination** port (including the IP protocol) of the packet.
>
> * The complete syntax to append the above rule to the `FORWARD` chain is
>   `iptables -A FORWARD -p udp -s 172.31.252.0/24 -d 172.31.250.0/24 -m udp
>   --sport 65001 -m state --state NEW -m set --match-set HDHR_CLIENTS dst,dst`.

## Using the Filter

Finally, FDF must be configured to use the IP set filter to add addresses and
ports to the IP set.

Create an instance of the filter.  For example:

```json
	"filters": {
		"ipset_hdhr": {
			"file": "./filters/ipset.so",
			"args": [ "set_name=HDHR_CLIENTS", "protocol=udp", "timeout=60" ]
		}
	}
```

The `set_name` parameter is required.  `protocol` (default UDP) and `timeout`
(default 30 seconds) are both optional.

Add it to the match.

```json
	"matches": {
		"hdhomerun": {
			"addr": "255.255.255.255",
			"port": 65001,
			"filters": [ "ipset_hdhr" ]
		}
	}
```

The daemon will now pass all broadcast packets that it receives on UDP port
`65001` to the IP set filter, which will add the source address and source port
of those packets to the `HDHR_CLIENTS` IP set.  The set entries will
automatically expire after one minute (unless another packet is received from
the same source, which will reset the timeout counter).
