# FDF - Flexible Discovery Forwarder

&copy; 2022 Ian Pilcher <<arequipeno@gmail.com>>

* [**Introduction**](#introduction)
* [**Building**](#building)
  * [Build Requirements](#build-requirements)
  * [Compiling](#compiling)
* [**Configuration**](#configuration)
  * [Filters](#filters)
  * [Matches](#matches)
    * [Filter Chaining](#filter-chaining)
  * [Listeners](#listeners)
  * [Validation](#validation)
* [**Running FDF**](#running-fdf)
  * [Runtime Requirements](#runtime-requirements)
  * [Running `fdfd`](#running-fdfd)

## Introduction

FDF is a highly configurable service that forwards broadcast and multicast
discovery packets between networks.

Many network devices use some type of discovery protocol, which allows them to
be automatically discovered by other devices or applications on the network.
Examples include:

* Google Chromecast devices
  ([multicast DNS](https://en.wikipedia.org/wiki/Multicast_DNS)),
* DLNA media servers
  ([SSDP](https://en.wikipedia.org/wiki/Simple_Service_Discovery_Protocol)),
* HDHomeRun television tuners, and
* Logitech Squeezebox and UE Radio devices.

Most of these discovery protocols have been developed with the assumption that
they will be used on a simple residential network with a single subnet on a
single [layer 2](https://en.wikipedia.org/wiki/Data_link_layer) domain
([segment](https://en.wikipedia.org/wiki/Network_segment)).  They mostly use
traffic types
([IPv4 broadcast](https://en.wikipedia.org/wiki/Broadcast_address#IP_networking)
or
[local subnetwork multicast](https://en.wikipedia.org/wiki/Multicast_address#IPv4))
that cannot be routed between networks.  Even when a discovery protocol does use
a routable multicast address (such as SSDP's `239.255.255.250`), multicast
routing capability is rare in residential routers, and it can be difficult to
configure on those devices and operating systems that do offer support.

As IoT and home automation devices have proliferated, and consumers have become
more conscious of privacy and security, more and more people want to separate
their residential network into multiple sub-networks in order to segretate
different device and traffic types and trust levels, and control which networks
and devices are allowed to communicate with one another (and with external
networks).  Of course, this breaks these discovery protocols.

Fortunately, most network discovery protocols work just fine as long as the
initial discovery message reaches the device or service to be discovered
**somehow**.  The "discoveree" typically does not verify that the discovery
message originated on its local network; it simply sends a response directly to
that message's source.  If the network has been configured to route the
response, it will be received by the "discoverer," and communication between the
two will proceed normally (assuming that the network has been configured to
route all of the required traffic).

FDF forwards broadcast and multicast discovery packets between networks, so
discovery protocols designed for "flat" networks can work in more complex
environments.  FDF is not normally involved in routing unicast discovery
responses; the network itself should be configured to route those packets.
(But see the [*IP Set*](doc/ipset-filter.md) and
[*nftables set*](doc/nftset-filter.md) filters.)

> **NOTE:** The multicast DNS (mDNS) protocol does not follow the traffic
> pattern described above.  mDNS queries and responses are **both** typically
> sent via IP multicast.  Thus, both queries and responses must be forwared to
> enable multicast DNS across separate networks.  See the
> [*Multicast DNS filter*](doc/mdns-filter.md).

## Building

### Build Requirements

FDF has been developed and tested on Linux and GCC.  Compatibility with other
operating systems and compilers is unknown.  (FDF does make use of several GCC
extensions, as well as the Linux-specific `epoll` API, and the
[IP set](doc/ipset-filter.md) and [nftables set](doc/nftset-filter.md) filters
are Linux-specific.)

FDF requires three libraries &mdash; [JSON-C](https://github.com/json-c/json-c)
and [libmnl](https://www.netfilter.org/projects/libmnl/index.html), which are
both commonly available in Linux distribution package repositories, and
[libSAVL](https://github.com/ipilcher/libsavl), which must be compiled and
installed as documented
[here](https://github.com/ipilcher/libsavl#building-and-installing-the-library).
The development packages or files for all three libraries must be installed in
order to build FDF and both included filters.

> **NOTE:** `libmnl` is required only by the
> [IP set](doc/ipset-filter.md) and [nftables set](doc/nftset-filter.md)
> filters, which are not required.

### Compiling

Ensure that the required libraries and development files are installed, clone
this repository, and change to its (`src`) directory.  For example:

```
$ rpm -q json-c-devel libmnl-devel libsavl-devel
json-c-devel-0.15-2.fc35.x86_64
libmnl-devel-1.0.4-14.fc35.x86_64
libsavl-devel-0.7.1-1.fc35.x86_64

$ git clone https://github.com/ipilcher/fdf.git
Cloning into 'fdf'...
remote: Enumerating objects: 27, done.
remote: Counting objects: 100% (27/27), done.
remote: Compressing objects: 100% (22/22), done.
remote: Total 27 (delta 5), reused 23 (delta 3), pack-reused 0
Receiving objects: 100% (27/27), 32.43 KiB | 2.16 MiB/s, done.
Resolving deltas: 100% (5/5), done.

$ cd fdf/src
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

Build some or all of the included filters.  For example:

```
$ cd filters

$ gcc -std=gnu99 -O3 -Wall -Wextra -Wcast-align -shared -fPIC -o mdns.so \
	-I.. mdns.c -lsavl

$ gcc -std=gnu99 -O3 -Wall -Wextra -Wcast-align -shared -fPIC -o ipset.so \
	-I.. ipset.c -lmnl

$ gcc -std=gnu99 -O3 -Wall -Wextra -Wcast-align -shared -fPIC -o nft-set.so \
	-I.. nft-set.c -lmnl
```

> **NOTE:**  The compiler options above provide maximum compatibility, across
> GCC versions.
>
> `-std=gnu99` is required only when using an older GCC version (such
> as GCC 4.8 on CentOS 7) that does not enable C99 features by default.
>
> `-Wcast-align` can help to identify alignment problems on platforms that
> differentiate (at the instruction set level) between aligned and unaligned
> memory access.  On these platforms, using aligned memory access instructions
> (which are preferred for performance reasons) with an incorrectly aligned
> address will cause a [bus error](https://en.wikipedia.org/wiki/Bus_error),
> which will usually terminate the program.  (Even worse, the processor may
> simply round the address down to a correctly aligned value, which will cause
> an incorrect memory location to be read or written.)  Many of the RISC
> processors in residential routers behave in one of these ways.
>
> x86 processors do not use different instructions for aligned and unaligned
> memory access (although use of unaligned addresses may affect performance or
> atomicity), so `-Wcast-align` has no effect when GCC is targeting an x86
> platform.  More recent versions of GCC support `-Wcast-align=strict`, which
> will cause GCC to issue alignment warnings even when it is targeting a
> platform that can tolerate unaligned memory access.

## Configuration

FDF uses a JSON configuration file to control its operation.  This configuration
file must contain a single JSON object (dictionary), and the top-level object
must contain 2 or 3 members.  The `matches` and `listen` members are required;
the `filters` member is optional.

> **NOTE:** FDF does not perform schema validation of its configuration file.
> As a result, additional object members at any level are silently ignored
> (including members with misspelled names).

The skeleton of a configuration file that includes a `filters` member appears
as follows.

```json
{
	"filters": {

	},
	"matches": {

	},
	"listen": {

	}
}
```

### Filters

The optional `filters` member of the configuration object specifies one or
more dynamically loaded filter modules (shared objects).  Filter modules can
be used to pass or drop packets based on their payload, forward a packet to a
specific network interface (see note in [**Listeners**](#listeners)), or
otherwise extend the functionality of the FDF daemon.  (See the
[*FDF Filter API*](doc/filter-api.md).)

FDF currently includes three filter modules.

* The [mDNS filter](doc/mdns-filter.md) provides stateless or stateful filtering
  of multicast DNS messages, based on message type and contents.

* The [IP set filter](doc/ipset-filter.md) does not actually filter traffic.
  Instead it adds the **source** address and port of any packet that it
  processes to a
  [Linux netfilter IP set](https://www.netfilter.org/projects/ipset/index.html).
  With the correct firewall rules in place, this can enable "stateful" routing
  of unicast responses to broadcast or multicast discovery packets; a unicast
  response packet will be routed only to a destination that recently sent a
  query of the correct type.

* The [nftables filter](doc/nftset-filter.md) is similar to the IP set filter,
  but it uses
  [nftables sets](https://wiki.nftables.org/wiki-nftables/index.php/Sets),
  rather than IP sets.

Each member of the `filters` object defines a filter instance of that name.
Each filter instance must contain 1 or 2 members &mdash; `file` (required) and
`args` (optional).  `file` must be a JSON string that specifies the full path of
the shared object to be loaded (unless the shared object is within the normal
library search path).  If present, `args` must be an array of JSON strings,
which will be passed to the filter's initialization function to initialize the
filter instance.  (The name of the filter instance and the path to the shared
object are also passed.)

The configuration fragment below creates two instances of the mDNS filter and
one instance of the IP set filter.

```json
	"filters": {
		"mdns_query": {
			"file": "./filters/mdns.so",
			"args": [ "mode=stateful", "forward=queries", "ipset=yes" ]
		},
		"mdns_response": {
			"file": "./filters/mdns.so",
			"args": [ "forward=responses" ]
		},
		"ipset_mdns": {
			"file": "./filters/ipset.so",
			"args": [ "set_name=MDNS_CLIENTS" ]
		}
	}
```

### Matches

The (required) `matches` member of the configuration object defines
address/port (or address/port/filters) tuples that identify network traffic.
As with filter instances, the name of the JSON member determines the name of
the match.

Each match must contain 2 or 3 members &mdash; `addr` (required), `port`
(required), and `filters` (optional).  `addr` must be a JSON string that
contains an IPv4 address, in standard dotted decimal notation.  The address
must be the IPv4 broadcast address (`255.255.255.255`) or an
[IPv4 multicast address](https://en.wikipedia.org/wiki/Multicast_address#IPv4).
`port` must be a JSON number (i.e. unquoted) that represents a valid UDP port
(`1` - `65535`).

> **NOTE:** FDF does not currently support IPv6.  Very few of the devices that
> use these protocols support IPv6, and none of them are IPv6-only.  (But see
> [this issue](https://github.com/ipilcher/fdf/issues/1).)

If present, `filters` must be an array of JSON strings, each of which is the
name of a filter instance defined in the `filters` object.  For each packet
received on the match's specified address and port, the filter instances will be
called in the order listed (unless a filter instance returns a value that
prevents subsequent filters from being called); see [below](#filter-chaining).

The configuration fragment below defines matches for several different types of
traffic, using the filter instances shown above.

```json
	"matches": {
		"mdns_query": {
			"addr": "224.0.0.251",
			"port": 5353,
			"filters": [ "mdns_query", "ipset_mdns" ]
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

#### Filter Chaining

The `mdns_query` match above is defined with multiple filter instances, a
configuration called a filter chain.  When a packet is received by a
[listener](#listeners)
that uses this match, the packet will be passed to each filter instance in the
chain sequentially (unless a filter instance returns a result value that
terminates filter processing of the packet).  In this configuration, the packet
will first be passed to the `mdns_query` filter instance.  Depending on the
value returned by `mdns_query`, the packet may then be passed to the
`ipset_mdns` filter instance.

The ultimate disposition of the packet (forwarded or dropped) is determined by
the values returned by the filter instances in the chain.  See
[Match Function](doc/filter-api.md#match-function) for more information.

> **NOTE:** It is not usually possible to arbitrarily chain filter modules.  The
> modules being chained must specifically support such use.  For example, the
> `mdns_query` filter instance [above](#filters) includes the `ipset=yes`
> argument.  This causes the mDNS filter to behave in a way that is compatible
> with this configuration.  (See [IP Set Mode](doc/mdns-filter.md#ip-set-mode).)

### Listeners

The (required) `listen` member of the configuration object specifies the network
interfaces on which FDF will listen, the types of traffic ([matches](#matches))
for which it will listen on those interfaces, and the networks to which matching
traffic will be forwarded.

Each member of the `listen` object identifies (by interface name) a network interface
on which FDF will listen.  Within that listen interface object, the name of each member
identifies a match defined in the [`matches`](#matches) object, and the value of each
member must be a list (array) of network interface names (JSON strings).

Each combination of a listen interface and a [`match`](#matches) defines a
**listener**.  Traffic that is received by a listener (and is not dropped due to
a filter return value) will be forwarded to all of the network interfaces listed
for that listener.

> **NOTE:** As discussed [above](#filters), it is possible for a filter to set
> a specific forward interface for a packet.  That interface must be one of the
> forward interfaces listed for the listener that received the packet.

For example, assume that FDF is running on a system with 4 network interfaces.

* `eth0` is connected to a trusted network,
* `eth1` is connected to an untrusted guest/wifi network,
* `eth2` is connected to an IOT network that has no Internet access, and
* `eth3` is connected to a storage network that uses jumbo frames for
  performance reasons.

Consider the following configuration fragment, which builds on the examples
above.

```json
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
  names within an object.  JSON-C (and most other parsers of which I am aware)
  deal with non-unique member names by simply ignoring all but one of the
  members.  As a result, FDF has no way to detect non-unique member names.

* As noted above, FDF itself does not detect unexpected or unknown object
  members in its configuration.  This is usually harmless, but it can be a
  problem if the name of a configuration member is misspelled, because the
  misspelled member will be ignored (silently if the member is optional).

The first two issues can be addressed by using a seperate JSON tool to validate
the configuration and check for duplicate member names.  `jsonlint`, part of the
[`demjson`](https://github.com/dmeranda/demjson) Python module, is one such
tool.  A similar tool is available online at
[`https://jsonlint.com/`](https://jsonlint.com).  The last issue could be
addressed by with a [JSON schema](https://json-schema.org).  (See
[this issue](https://github.com/ipilcher/fdf/issues/2).)

## Running FDF

### Runtime Requirements

Running `fdfd` requires JSON-C, libSAVL, and (if using the IP set or nftables
set filter) libmnl.  The corresponding development files are not needed just to
run the daemon.

It also has several network-related requirements.

* All interfaces on which `fdfd` will listen must have at least one
  IPv4 address configured.  If no address is configured, `fdfd` will not
  issue any error message, because it does not make use of the IP address, but
  it will not actually receive any traffic from that interface.  (This appears
  to be a Linux kernel behavior.)

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

Finally, the daemon must run either as the `root` user or with certain
[capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html).

* In order to forward a packet, `fdfd` re-sends it with its source IP address
  address unchanged &mdash; i.e., set to the packet's original source address,
  rather than the address of the system on which `fdfd` is running.  This
  requires the use of a
  [raw socket](https://man7.org/linux/man-pages/man7/raw.7.html).  If the daemon
  is not running as `root`, it must run with the `CAP_NET_RAW` capability.

* When using the [IP set](doc/ipset-filter.md) or
  [nftables set](doc/nftset-filter.md)as a non-`root` user, `fdfd` must run with
  the `CAP_NET_ADMIN` capability in order to modify the set contents.

### Running `fdfd`

To run `fdfd` from a command prompt, create a configuration file and execute
`fdfd` (usually as `root`) with any required command line options.  `fdfd`
accepts the following options.

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

* Copy the included filters to the filter plugin directory.

* Copy the configuration file to `/etc/fdf-config.json`.

* Make `systemd` aware of the new service with `systemctl daemon-reloaad`.

* Start the service (`systemctl start fdfd`) or start and enable the service
  (`systemctl enable fdfd --now`).

* Check for errors (`systemctl status fdfd`).

For example (from the top-level directory of the repository):

```
# cp systemd/fdfd.service /etc/systemd/sytem/

# cp src/fdfd /usr/local/bin/

# mkdir /usr/local/lib64/fdf-filters

# cp src/filters/*.so /usr/local/lib64/fdf-filters/

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
