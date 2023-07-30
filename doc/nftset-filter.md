# nftables Set Filter (`nft-set.so`)

&copy; 2023 Ian Pilcher <<arequipeno@gmail.com>>

* [**Introduction**](#introduction)
* [**nftables Sets**](#nftables-sets)
* [**nftables Rules**](#nftables-rules)
* [**Filter Arguments**](#filter-arguments)

## Introduction

[**nftables**](http://nftables.org/projects/nftables/index.html) was introduced
in Linux kernel 3.13.  It replaces older network filter mechanisms such as
iptables, ip6tables, ebtables, etc.  Additionally, it includes set functionality
that replaces the older IP set feature.

This filter operates identically to the [IP set filter](ipset-filter.md), except
that it manages entries in nftables sets rather than IP sets.

See the [*IP Set Filter* documentation](ipset-filter.md) for an overview of the
usage of that filter, as this document only covers areas in which the two
filters differ.

## nftables Sets

This filter manages named sets, which exist within the scope of a single
nftables **table**.  Each table is associated with a single **address family**
&mdash; `ip` (IPv4 only), `ip6` (IPv6 only), `inet` (IPv4 or IPv6), etc.  FDF
does not currently support IPv6, so this filter can only manage sets within
`ip` and `inet` tables.

The element type of the set must be a concatenated type, consisting of an IPv4
address (`ipv4_addr`) and a UDP/TCP port number (`inet_service`).  The set must
have the `timeout` flag set.

> **NOTE:** Unlike the `hash:ip,port` set type used by the IP set filter, the
> layer 4 protocol (UDP or TCP) is not part of the `inet_service`.  Thus, the
> same element type can be used for either UDP or TCP port numbers.

For example, this set is used to (temporarily) hold the addresses and UDP port
numbers from which Logitech Media Server (SlimServer, SqueezeboxServer, etc.)
discovery packets have been received.

```
table inet filter {
        set LMS_CLIENTS {
                type ipv4_addr . inet_service
                flags timeout
        }
}
```

Such a set could be created with the following command.

```
# nft add set inet filter LMS_CLIENTS \
	'{ type ipv4_addr . inet_service ; flags timeout ; }'
```

Unlike IP sets, no separate service is required to re-create nftables sets at
boot time.  They can be defined within the system's nftables configuration.

## nftables Rules

Continuing with the Logitech Media Server (LMS) example, the following rule can
be used to accept LMS response packets that originate at `192.168.248.1`.

```
ip saddr 192.168.248.1 udp sport 3483 ip daddr . udp dport @LMS_CLIENTS accept
```

## Filter Arguments

The filter accepts the following arguments.

* `table_name` (*required*) &mdash; The name of the nftables table which
  contains the set to be managed.

* `set_name` (*required*) &mdash; The name of the set to be managed.

* `address_family` (*optional*) &mdash; The address family of the table (`ip` or
  `inet`).  Defaults to `inet` if not specified.

* `timeout` (*optional*) &mdash; The length of time, in seconds, that an entry
  remains in the set (if no additional discovery packets are received).
  Defaults to 30 seconds if not specified.  `timeout=0` will cause entries to
  never expire.
