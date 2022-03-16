# Multicast DNS Filter (`mdns.so`)

&copy; 2022 Ian Pilcher <<arequipeno@gmail.com>>

## Protocol

Multicast DNS (mDNS) uses a different communication pattern than other
discovery protocols.  Where other protocols use a broadcast (or multicast)
discovery message and direct unicast responses, mDNS usually uses multicast
for both queries and responses.  Both are sent to the same destination &mdash;
`224.0.0.251:5353` or `[ff02::fb]:5353`.  To enable mDNS-based discovery across
different networks, both queries and responses must be forwarded.

> **NOTE:** An mDNS query may contain a flag which requests a unicast response
> (the `QU` bit).  If responders honor this request, then the traffic will
> follow the "normal" discovery protocol pattern.
>
> (An mDNS responder may also send a unicast response if it receives a query
> sent directly to its IP address.  Because all of the traffic in this
> scenario is routable, no forwarding is required.)

## Forwarding

Several multicast DNS forwarders exist.  To my knowledge, however, all of them
forward **all** mDNS traffic from a network to one or more other networks,
with no differentiation between queries and answers.  This may not be
desirable.

Consider a scenario with two networks &mdash; a trusted network connected to
`eth0` and an untrusted network connected to `eth1`.  Resources on the untrusted
network should be discoverable from the trusted network, but the reverse should
not be true.  If all mDNS traffic is forwarded between the two networks,
however, anything connected to the untrusted network will be able to perform
mDNS-based discovery of resources on the trusted network.

## Filter

The multicast DNS filter (`mdns.so`) which allows for more precise control.
Queries and answers are identified, which allows different forwarding rules to
be applied to messages of different types.

The filter can also operate in a **stateful** mode, in which an answer is only
forwarded if it answers a query that was previously forwarded.  More
specifically:

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

## Configuration

The mDNS filter accepts several parameters.  All parameters are passed in a
`<name>=<value>` format.

The `mode` and `query_life` parameters are global.  Each of them can be
specified at most once in the FDF configuration.

* `mode={stateless|stateful}` (default `stateless`) &mdash; Determines whether
  the filter will operate in stateless or stateful mode, as described
  [above](#filter).

* `query_life=<seconds>` (default `30` seconds) &mdash; In **stateful** mode,
  determines the lifetime of a forwarded query record.  After the lifetime has
  expired, the record is dropped, and answers that match the query will no
  longer be forwarded.  (This parameter has no effect in **stateless** mode.)

The `forward` and `ipset` parameters operate on individual filter instances.
Each of them can (or must) be specified for each instance of the mDNS filter.

* `forward={queries|responses}` (**required**) &mdash;  Determines whether
  this instance of the filter forwards query or response (answer) messages.

  > **NOTE:** FDF filters do not actually drop or forward network traffic.
  > The filter's `match` function returns one of several `PASS` or `DROP` values
  > to the daemon, and the daemon's ultimate action may be affected by other
  > filters.

* `ipset={yes|no|true|false}` (default `no`) &mdash; Determines whether the
  mDNS filter operates in "[IP set mode](#ip-set-mode)," which better supports
  "chaining" the mDNS and [IP set](ipset-filter.md) filters.

### IP Set Mode

The [IP set filter](ipset-filter.md) can be used to dynamically enable routing
of unicast responses to broadcast and multicast discovery packets.  As discussed
[above](#protocol), this is not usually needed for multicast DNS traffic,
because mDNS responses are normally sent via multicast.  As noted, however, a
multicast DNS query may request a unicast response by setting its `QU` bit.  In
this case, there is a requirement to route a unicast response packet.

Together, the mDNS and IP set filters support this scenario through
[filter chaining](../README.md#filter-chaining).  Returning to the example
of a trusted network connected to `eth0` and an untrusted network on `eth1`,
an FDF configuration might look like this.

```json
{
	"filters": {
		"mdns_query": {
			"file": "./filters/mdns.so",
			"args": [ "mode=stateful", "forward=queries" ]
		},
		"mdns_response": {
			"file": "./filters/mdns.so",
			"args": [ "forward=responses" ]
		}
	},
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
		}
	},
	"listen": {
		"eth0": {
			"mdns_query": [ "eth1" ]
		},
		"eth1": {
			"mdns_response": [ "eth0" ]
		}
	}
}
```

This configuration forwards (multicast) mDNS queries from `eth0` to `eth1`, and
it forwards multicast mDNS responses from `eth1` to `eth0`.  (It uses stateful
mode, so only responses to queries that originated on the trusted network are
forwarded to that network.)

This configuration does not do anything to enable routing of **unicast** mDNS
responses from the untrusted network to the trusted network.  That requires
adding the IP set filter.

```json
{
	"filters": {
		"mdns_query": {
			"file": "./filters/mdns.so",
			"args": [ "mode=stateful", "forward=queries" ]
		},
		"mdns_response": {
			"file": "./filters/mdns.so",
			"args": [ "forward=responses" ]
		},
		"ipset_mdns": {
			"file": "./filters/ipset.so",
			"args": [ "set_name=MDNS_CLIENTS" ]
		}
	},
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
		}
	},
	"listen": {
		"eth0": {
			"mdns_query": [ "eth1" ]
		},
		"eth1": {
			"mdns_response": [ "eth0" ]
		}
	}
}
```

Consider a UDP packet addressed to `224.0.0.251:5353` to that is received on
`eth0` (the trusted network interface).  Leaving aside error conditions, there
are three possibilities:

1. If the packet containes an mDNS query with the `QU` bit set, the
   `mdns_query` filter instance will return `FDF_FILTER_PASS`.  The packet will
   then be passed to the `ipset_mdns` filter instance which will add the
   packet's source IP address and port to the `MDNS_CLIENTS` IP set.  The
   `ipset_mdns` filter instance will then return `FDF_FILTER_PASS` (because it
   always does), and FDF will forward the packet to the untrusted network.

   If the firewall is configured correctly, any unicast responses received in
   the next 30 seconds (the IP set filter's default timeout) will be routed to
   the address from which the query originated.  This is the desired behavior.

2. If the packet contains an mDNS query that does not have the `QU` bit set, the
   result will be identical.  The `mdns_query` filter instance will return
   `FDF_FILTER_PASS` (because it is a query), then the `ipset_mdns` filter
   instance will will add the query's source address and port to the
   `MDNS_CLIENTS` IP set (because that's what it does) and return
   `FDF_FILTER_PASS`.  FDF will forward the packet to the untrusted network.

   This is the desired result, except that the source address of the query has
   been incorrectly added to the `MDNS_CLIENTS` IP set, as there is no reason to
   expect any unicast responses to the query.

3. If the packet does not contain an mDNS query (usually because it contains a
   multicast response), the `mdns_query` filter instance will properly return
   `FDF_FILTER_DROP`.  However, the packet will still be passed to the
   `ipset_mdns` filter instance, which will add its source address to the
   `MDNS_CLIENTS` IP set and return `FDF_FILTER_PASS` (because it does not have
   any visibility into the results of previous filters in the chain).

   Because the last filter in the chain returned `FDF_FILTER_PASS`, FDF will
   forward the packet to the untrusted network, which is definitely not the
   desired result.

The mDNS filter's IP set mode changes the result that the filter returns in
scenarios **2** and **3**.

* If the packet contains an mDNS query that does not have the `QU` bit set
  (scenario **2**), the `mdns_query` filter instance will return
  `FDF_FILTER_PASS_NOW`.  This will cause the FDF daemon to immediately stop
  filter processing and forward the packet to the untrusted network.  The
  packet will not be passed to the `ipset_mdns` filter instance, so its source
  address will not be added to the `MDNS_CLIENTS` IP set.

* If the packet does not contain an mDNS query (scenario **3**), the
  `mdns_query` filter instance will return `FDF_FILTER_DROP_NOW`.  The daemon
  will immediately stop filter processing and drop the packet.  The packet will
  not be passed to the `ipset_mdns` filter instance, so its source address will
  not be added to the `MDNS_CLIENTS` IP set.

The complete correct configuration is:

```json
{
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
	},
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
		}
	},
	"listen": {
		"eth0": {
			"mdns_query": [ "eth1" ]
		},
		"eth1": {
			"mdns_response": [ "eth0" ]
		}
	}
}
```
