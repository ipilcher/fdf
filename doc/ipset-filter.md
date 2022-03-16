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
**unicast** answer.  Often, those answers must be **routed** from an untrusted
network to a trusted network, in response to a discovery message that was
**forwarded** from the trusted network to the untrusted network.  A stateful
firewall will normally drop (or reject) such response packets, because their
relationship to the initial discovery message isn't understood by the firewall.
(After all, the firewall didn't route the discovery packet.  Some application
sent **something** with a raw socket, but it wasn't even addressed to the
address from which the response packets are coming.)

The simplest solution to this problem is to unconditionally allow the responses
to be routed.  For example:

```
Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
	︙
    0     0 ACCEPT     udp  --  *      *       172.31.252.4         172.31.250.0/24      udp spt:65001 state NEW
	︙
```

This example assumes that the firewall is using
[Linux `iptables`](https://www.netfilter.org/projects/iptables/index.html).  It
allows any packets from UDP port `65001` (the port used by HDHomeRun tuner
discovery) at `172.31.252.4` (the known address of the tuner) to be routed to
any address on the trusted network (`172.31.250.0/24`).  HDHomeRun tuners do not
support static IP addressing, so absent a DHCP reservation the rule would have
to look like this.

```
Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
	︙
    0     0 ACCEPT     udp  --  *      *       172.31.252.0/24      172.31.250.0/24      udp spt:65001 state NEW
	︙
```

This now allows anything on the `172.31.252.0/24` network to send UDP traffic
from port `65001` to the trusted network.  (And keep in mind that the sender
controls the source port.)

This is unlikely to be a significant vulnerability, but it's still not ideal.
Wouldn't it be nice to only route such traffic to the specific address and port
from which a recent discovery packet originated?  The IP set "filter," along
with the correct firewall configuration enables this.

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

> **NOTE:** `timeout 0` sets the default timeout of set entries to zero, which
> means that entries will not be automatically removed from the set.  The set
> default doesn't matter, because the IP set filter will explicitly the timeout
> of each entry that it adds, but some timeout value must be specified in order
> to create a set with timeout support.
>
> `hashsize 64` creates a set with the smallest possible initial memory
> footprint.  The kernel will automatically expand the set if its initial size
> is inadequate, and `64` will almost certainly be adequate for any home
> network, so this is the recommended size.

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

With the set in place, it can used in the `iptables` rule.  (Again assuming that
the address(es) of the HDHomeRun tuner(s) aren't known.)

```
Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
	︙
    0     0 ACCEPT     udp  --  *      *       172.31.252.0/24      172.31.250.0/24      udp spt:65001 state NEW match-set HDHR_CLIENTS dst,dst
	︙
```

> **NOTE:** The `match-set` option is provided by the `set` module.  The
> `dst,dst` flags correspond to the data types in the set entries.  The set
> type is `hash:ip,set`, so `dst,dst` means that the rule will match only if the
> set contains an entry that matches the **destination** IP address and
> **destination** port (including the IP protocol) of the packet.
>
> The complete syntax to append the above rule to the `FORWARD` chain is
> `iptables -A FORWARD -p udp -s 172.31.252.0/24 -d 172.31.250.0/24 -m udp
> --sport 65001 -m state --state NEW -m set --match-set HDHR_CLIENTS dst,dst`.

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
