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
  mDNS filter operates in "ipset mode," which better supports "chaining" the
  mDNS and [IP set](ipset-filter.md) filters.  See
  [`mdns-ipset.md`](mdns-ipset.md).
