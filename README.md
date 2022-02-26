# FDF - Flexible Discovery Forwarder

&copy; 2022 Ian Pilcher <<arequipeno@gmail.com>>

* [**Introduction**](#introduction)
  * [Multicast DNS](#multicast-dns)
* [**Building**](#building)
  * [Build Requirements](#build-requirements)
  * [Compiling](#compiling)
* [**Configuration**](#configuration)
  * [Filters](#filters)
  * [Matches](#matches)
  * [Listeners](#listeners)
  * [Validation](#validation)
* [**Running FDF**](#running-fdf)
  * [Runtime Requirements](#runtime-requirements)
  * [Running `fdfd`](#running-fdfd)

## Introduction

FDF is a highly configurable service that forwards broadcast and multicast
discovery packets between networks.

Many networked consumer devices use some type of discovery protocol, allowing
them to be automatically discovered on home networks.  Examples include:

* Google Chromecast devices
* DLNA media servers
* HDHomeRun television tuners
* Logitech Squeezebox and UE Radio devices

These protocols mostly assume that they are being used on a simple, flat
home network.  They use traffic types (IPv4 broadcast and local subnetwork
multicast) that cannot be routed between networks.  Even when a protocol uses a
routable multicast address (such as SSDP's `239.255.255.250`), very few
residential networks actually support multicast routing.

More technical users, however, often want to separate their home networks into
multiple VLANs/subnets in order to segregate different device types, traffic,
and trust levels, and control which networks and devices are allowed to
communicate with one another.  Of course, this breaks these discovery
protocols.

In fact though, most such devices work just fine as long as the discovery
packets reach the device.  The devices do not check that the discovery packet
came from an address on their local network; they simply send a **unicast**
response to the discovery packet's source address, which can be routed by normal
means.

FDF forwards broadcast and multicast discovery packets between different
networks, enabling discovery protocols designed for flat networks to work
across multiple subnets.  (FDF does **not** concern itself with unicast
responses.  Routing of those packets must be enabled via the normal mechanism
used in the network.)

### Multicast DNS

Multicast DNS (mDNS) does not usually operate as described above.  Queries and
responses are both normally sent via multicast (unless the query specifically
requests a unicast response).  Queries and responses are both sent to the
same destination &mdash; `224.0.0.251:5353` or `[ff02::fb]:5353`.  Thus, FDF
must forward both mDNS queries and mDNS responses.

Other mDNS forwarders exist, but (to my knowledge) all of them simply forward
all mDNS traffic on a particular network interface to one or more other
interfaces, without discriminating between queries and responses.  So using one
of these forwarders to enable discovery of devices on an untrusted network from
a trusted network also has the reverse effect; mDNS responders on the trusted
network can be discovered from the untrusted network.

FDF includes a [filter](#filters) (`mdns.so`) which allows for more precise
control.

* In **stateless** mode, the mDNS filter examines the header of the packets
  that it receives and determines whether each packet is a query or an response.
  Each instance of the filter is configured to pass either queries or responses
  and drop other types of packets.  This enables a simple "directional" filter;
  queries are forwarded from the trusted network to the untrusted network, and
  responses can be forwarded the other way.

  In this mode, an instance of the mDNS filter configured to pass responses
  will forward all mDNS response packets that it receives, regardless of the
  source of the query that triggered that response (if any).

* In **stateful** mode, the filter tracks the mDNS requests that it receives
  and the network from which it originated.  Responses that do not match a
  request received within a configurable timeframe are dropped.  Responses that
  do match a previous request are forwarded only to the network from which that
  request was received.

## Building

### Build Requirements

FDF has been developed and tested on Linux and GCC.  Compatibility with other
operating systems and compilers is unknown.  (FDF does make use of several GCC
extensions.)

FDF requires 2 libraries &mdash; [JSON-C](https://github.com/json-c/json-c),
which is commonly available in Linux distribution package repositories, and
[libSAVL](https://github.com/ipilcher/libsavl), which must be compiled and
installed as documented
[here](https://github.com/ipilcher/libsavl#building-and-installing-the-library).
The development packages/files for both libraries must be installed in order to
build FDF.

### Compiling

Ensure that the required libraries and development files are installed, clone
this repository, and change to its top-level (`fdf`) directory.  For example:

```
$ rpm -q json-c-devel libsavl-devel
json-c-devel-0.15-2.fc35.x86_64
libsavl-devel-0.7.1-1.fc35.x86_64

$ git clone https://github.com/ipilcher/fdf.git
Cloning into 'fdf'...
remote: Enumerating objects: 27, done.
remote: Counting objects: 100% (27/27), done.
remote: Compressing objects: 100% (22/22), done.
remote: Total 27 (delta 5), reused 23 (delta 3), pack-reused 0
Receiving objects: 100% (27/27), 32.43 KiB | 2.16 MiB/s, done.
Resolving deltas: 100% (5/5), done.

$ cd fdf
```

Ensure that the filter API version in `fdf-filter.h` is up to date.

```
$ ./apiver.sh
```

Build the daemon (`fdfd`).

```
$ gcc -std=gnu99 -O3 -Wall -Wextra -Wcast-align -o fdfd *.c -lsavl -ljson-c \
	-ldl -Wl,--dynamic-list=symlist
```

> **NOTE:** The `-std=gnu99` option is required only with older compilers (such
> as GCC 4.8 on CentOS 7) that do not enable C99 features by default, but it
> does no harm on newer versions.  Similarly, `-Wcast-align` has no effect on
> platforms such as x86 that don't differentiate between aligned and unaligned
> memory access; it is significant, however, on platforms such as ARM that will
> trigger a bus error when aligned memory access instructions are used with an
> unaligned address.

Build the multicast DNS filter (`mdns.so`).

```
$ cd filters

$ gcc -std=gnu99 -O3 -Wall -Wextra -shared -fPIC -o mdns.so -I.. mdns.c
```

## Configuration

FDF uses a JSON configuration file to control its operation.  This configuration
file must contain a single JSON object (dictionary), and the top-level object
must contain 2 or 3 members.  The `matches` and `listen` members are required,
and the `filters` member is optional.

> **NOTE:** FDF does not perform schema validation of its configuration file.
> As a result, additional object members at any level are silently ignored
> (including members with misspelled names).

The skeleton of a configuration file that includes a `filters` member appears
as follows.

```
{
	"filters": {
		︙
	},
	"matches": {
		︙
	},
	"listen": {
		︙
	}
}
```

### Filters

The optional `filters` member of the configuration object specifies one or
more dynamically loaded filter modules (shared objects).  Filter modules can
be used to pass or drop packets, based on the packet contents.  A filter module
can also specify a particular network interface to which a packet should be
forwarded.  (See the note in [**Listeners**](#listeners) for a discussion of
this feature.)

Each member of the `filters` object defines a filter instance.  Each filter
instance must have a unique name, which is defined by its name (key value)
within the `filters` object.  Each filter instance must contain 1 or 2 members
&mdash; `file` (required) and `args` (optional).  `file` must be a JSON string
that specifies the full path of the shared object to be loaded (unless the
shared object is within the normal library search path).  If present, `args`
must be an array of JSON strings, which will be passed to the filter's
initialization function to initialize the filter instance.  (The name of the
filter instance and the path to the shared object are also passed.)

FDF includes a [multicast DNS filter](#multicast-dns) (`mdns.so`).  The
configuration fragment below creates 2 instances of this filter.

```
	"filters": {
		"mdns_query": {
			"file": "./filters/mdns.so",
			"args": [ "mode=stateful", "accept=queries" ]
		},
		"mdns_response": {
			"file": "./filters/mdns.so",
			"args": [ "accept=responses" ]
		}
	}
```

### Matches

The (required) `matches` member of the configuration object defines
address/port (or address/port/filter) tuples that uniquely identify types of
traffic.

As with filter instances, each match must have a unique name that is determined
by its member name within the `matches` object.  Each match must be a JSON
object that contains 2 or 3 members &mdash; `addr` (required), `port`
(required), and `filters` (optional).  `addr` must be a JSON string that
contains an IPv4 address, in standard dotted decimal notation.  The address
must be the IPv4 broadcast address (`255.255.255.255`) or an
[IPv4 multicast address](https://en.wikipedia.org/wiki/Multicast_address#IPv4).
`port` must be a JSON number (i.e. unquoted) that represents a valid UDP port
(`1` - `65536`).

> **NOTE:** FDF does not currently support IPv6.  Very few of the devices that
> use these protocols support IPv6, and none of them are IPv6-only.  (But see
> [this issue](https://github.com/ipilcher/fdf/issues/1).)

If present, `filters` must be an array of JSON strings, each of which is the
name of a filter instance defined in the `filters` object.  For each packet
received on the match's specified address and port, the filter instances will be
called in the order listed (unless a filter instance returns a value that
prevents subsequent filters from being called).

The configuration fragment below defines matches for several different types of
traffic, using the filter instances shown above.

```
	"matches": {
		"mdns_query": {
			"addr": "224.0.0.251",
			"port": 5353,
			"filters": [ "mdns_query" ]
		},
		"mdns_response": {
			"addr": "224.0.0.251",
			"port": 5353,
			"filters": [ "mdns_response" ]
		},
		"ssdp": {
			"addr": "239.255.255.250",
			"port": 1900
		},
		"hdhomerun": {
			"addr": "255.255.255.255",
			"port": 65001
		}
	}
```

### Listeners

The (required) `listen` member of the configuration object specifies what types
of traffic (matches) FDF will listen for, the network interfaces on which it
will listen for that traffic, and the networks to which the traffic will be
forwarded.

Each member within the `listen` object applies to a specific network interface
on which FDF will listen.  The name of the member is the name of the network
interface.  Within that object (the listen interface), the name of each member
identifies a match defined in the `matches` object, and the value of each
member must be an array of strings that list the destination network interraces
for traffic received on that particular listen interface/match combination.

> **NOTE:** In general, any packet received by a particular network
> interface/match combination (and passed by the match's filter instances, if
> any) will be forwarded to **all** of the destination interfaces listed for
> that combination.  As discussed [above](#filters), however, it is possible for
> a filter to set a specific destination interface, which must be one of the
> destination interfaces listed for that interface/match combination.

For example, assume that FDF is running on a system with 4 network interfaces.
`eth0` is connected to a trusted network, `eth1` is connected to an untrusted
guest/wifi network, `eth2` is connected to an IOT network that has no Internet
access, and `eth3` is connected to a storage network that uses jumbo frames for
performance reasons.

Consider the following configuration fragment, which builds on the `matches`
example above.

```
	"listen": {
		"eth0": {
			"mdns_query": [ "eth1" ],
			"hdhomerun": [ "eth2" ]
		},
		"eth1": {
			"mdns_response": [ "eth0", "eth3" ],
			"ssdp": [ "eth3" ]
		},
		"eth3": {
			"mdns_query": [ "eth1" ]
		}
	}
```

This configuration has the following effects.

* Devices on the trusted network (`eth0`) can use multicast DNS to discover
  Chromecast devices on the guest/wifi network (`eth1`).  The `mdns_query`
  member within `eth0` causes the requests to be forwarded, and the
  `mdns_response` member in `eth1` causes the responses to be forwarded.
  (The mDNS filter is operating in stateful mode, so only responses to a query
  that actually came from the trusted network will be forwarded to that
  network.)

* Devices on the trusted network (`eth0`) can also discover HDHomeRun tuner
  devices on the IOT network (`eth2`), because of the `hdhomerun` member within
  `eth0`.  The HDHomeRun discovery protocol uses unicast responses, so no
  further FDF configuration is required to make this work (but the network must
  be set up to route the responses).

* Devices on the guest/wifi network (`eth1`) can use SSDP to discover the DLNA
  media server running on the NAS, which is connected to the storage network
  (`eth3`).  SSDP uses unicast responses, so the `ssdp` member within `eth1`
  provides the only required FDF configuration.

* Finally, the `mdns_query` member within `eth3` allows the media server on the
  NAS (connected to the storage network, `eth3`) to send multicast DNS queries
  to the guest/wifi network (`eth1`) for Chromecast discovery.  As with mDNS
  requests from `eth0`, the `mdns_response` member of `eth1` is required to
  forward responses back to the network from which their corresponding query
  came.

### Validation

FDF uses the [JSON-C library](https://github.com/json-c/json-c) to parse its
configuration.  JSON-C has numerous benefits, but it does have some limitations.

* JSON-C's error messages can be unhelpful.  FDF itself will report errors that
  it detects (missing required members or incorrect JSON types), but JSON that
  is actually invalid will be reported as a JSON-C error.

* The [JSON specification](https://datatracker.ietf.org/doc/html/rfc7159) does
  not specify the behavior of JSON parsers in the presence of non-unique member
  names within an object.  JSON-C (and all other parsers of which I am aware)
  deal with non-unique member names by simply ignoring all but one of the
  members.  As a result, FDF has no way to detect non-unique member names.

* As noted above, FDF itself does not detect unexpected/unknown object members
  in its configuration.  This is mostly harmless, except in the event that the
  name of an actual configuration member is misspelled.

The first two issues can be addressed by using a seperate JSON tool that can
validate the configuration and check for duplicate keys (member names).
`jsonlint`, part of the [`demjson`](https://github.com/dmeranda/demjson) Python
module, is one such tool.  A similar tool is available online at
[`https://jsonlint.com/`](https://jsonlint.com).  The last issue can be
addressed by the development of a suitable
[JSON schema](https://json-schema.org) for FDF configurations.  (See
[this issue](https://github.com/ipilcher/fdf/issues/2).)

## Running FDF

### Runtime Requirements

Running `fdfd` requires that JSON-C and libSAVL (but not necessarily their
development files) are installed.  It also has several network-related
requirements.

* Interfaces on which `fdfd` will listen for traffic must have at least one IPv4
  address configured.  If no such address is configured, `fdfd` will not
  issue any error message, because it does not make use of the IP address, but
  it will not actually receive any traffic from that interface.

* The host firewall (`iptables`, `nftables`, `firewalld`, etc.) of the system on
  which `fdfd` is running must be configured to allow the daemon's traffic.
  Most Linux distributions' default firewall configurations allow all outbound
  traffic, but they block almost all new inbound connections, so additional
  rules will most likely be needed for all types of traffic to which `fdfd` will
  listen.

* The network must be configured to route unicast response packets back to the
  networks from which discovery packets originate.  It may also be necessary to
  configure the host firewall on the devices sending the discovery packets;
  responses (unicast or multicast) will usually not be recognized as being
  related to a preceding query, so the host firewall will treat them as new,
  unsolicited connections.

> **NOTE:** When forwarding a packet to a network to which it would not normally
> be routed, `fdfd` must send the packet with its source IP address unchanged
> (i.e. set to the packet's original source address, rather than the address
> of the system on which `fdfd` is running).  This requires a
> [raw socket](https://man7.org/linux/man-pages/man7/raw.7.html).  In order to
> create a raw socket, `fdfd` must be run as the `root` user or with the
> [`CAP_NET_RAW` capability](https://man7.org/linux/man-pages/man7/capabilities.7.html).

### Running `fdfd`

To run `fdfd` from a command prompt, create a configuration file and execute
`fdfd` with any required command line options.  `fdfd` accepts the following
options.

* `-l` or `--syslog` specifies that all log messages should be sent to the
  system log.  Log messages are normally sent to `stderr` if it is connected to
  a terminal.

* `-e` or `--stderr` specifies that all log messages should be sent to `stderr`,
  even if it is not connected to a terminal.  This option is useful when
  running `ndfd` from the command line with `stderr` redirected to a file or
  piped to another program (such as `less` or `tee`).

* `-d` or `--debug` enables logging of `DEBUG` level messages.  Normally, only
  `INFO` or higher priority messages are logged.

* `-p` or `--pktlog` enables logging of `INFO` level messages related to
  individual packets, including packet-specific `INFO` level messages issued by
  filters.

* `-c` or `--config`, followed by the absolute or relative path of an FDF
  configuration, file overrides the default configuration file location,
  `/etc/fdf-config.json`.

* `-h` or `--help` causes `fdfd` to print a brief summary of these options to
  `stdout` and exit.

> **NOTE:** Both `-d` and `-p` (or their longer equivalents) must be specified
> to enable logging of packet-specific `DEBUG` level messages from filters.

`fdfd` can also be run as a `systemd` service, using the unit file in this
repository (`fdfd.service`).  To use the unit file unchanged, perform the
following steps as the `root` user.

* Copy the unit file to `/etc/systemd/system/`.

* Copy the daemon executable to `/usr/local/bin/`.

* Create a directory for filter plugins &mdash; `/usr/local/lib/fdf-filters` or
  `/usr/local/lib64/fdf-filters`.

* Copy the multicast DNS filter to the filter plugin directory.

* Copy the configuration file to `/etc/fdf-config.json`.

* Make `systemd` aware of the new service with `systemctl daemon-reloaad`.

* Start the service (`systemctl start fdfd`) or start and enable the service
  (`systemctl enable fdfd --now`).

* Check for errors (`systemctl status fdfd`).

For example:

```
# cp fdfd.service /etc/systemd/sytem/

# cp fdfd /usr/local/bin/

# mkdir /usr/local/lib64/fdf-filters

# cp mdns.so /usr/local/lib64/fdf-filters/

# cp fdf-config.json /etc/

# systemctl daemon-reload

# systemctl enable fdfd --now
Created symlink from /etc/systemd/system/multi-user.target.wants/fdfd.service to /etc/systemd/system/fdfd.service.

# systemctl status fdfd
● fdfd.service - Flexible Discovery Forwarder daemon
   Loaded: loaded (/etc/systemd/system/fdfd.service; enabled; vendor preset: disabled)
   Active: active (running) since Sat 2022-02-26 17:33:49 CST; 36s ago
 Main PID: 18317 (fdfd)
   CGroup: /system.slice/fdfd.service
           └─18317 /usr/local/bin/fdfd

Feb 26 17:33:49 asterisk.penurio.us systemd[1]: Started Flexible Discovery Forwarder daemon.
Feb 26 17:33:49 asterisk.penurio.us fdfd[18317]: INFO: filter.c:214: Loaded filter (mdns_query..." ]
Feb 26 17:33:49 asterisk.penurio.us fdfd[18317]: INFO: filter.c:214: Loaded filter (mdns_answe..." ]
Hint: Some lines were ellipsized, use -l to show in full.
```
