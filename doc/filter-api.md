# FDF Filter API

&copy; 2022 Ian Pilcher <<arequipeno@gmail.com>>

* [**Introduction**](#introduction)
* [**Filter API Header**](#filter-api-header)
  * [API Version](#api-version)
  * [Module Registration](#module-registration)
  * [Initialization Function](#initialization-function)
  * [Cleanup Function](#cleanup-function)
  * [Match Function](#match-function)
  * [Helper Functions](#helper-functions)
    * [`fdf_filter_log()]`](#fdf_filter_log)
    * [`fdf_filter_sock_addr()`](#fdf_filter_sock_addr)
    * [`fdf_filter_netif_name()`](#fdf_filter_netif_name)
    * [`fdf_filter_set_data()`](#fdf_filter_set_data)
    * [`fdf_filter_get_data()`](#fdf_filter_get_data)
* [**Building a Filter Module**](#building-a-filter-module)
* [**Installing and Using a Filter Module**](#installing-and-using-a-filter-module)

## Introduction

FDF filters are dynamically loaded modules that extend the functionality of the
service.  FDF includes two filters &mdash; the
[multicast DNS filter](mdns-filter.md) and the [IP set filter](ipset-filter.md),
but additional filters can be created

## Filter API Header

The FDF filter API is defined by its header file &mdash; `fdf-filter.h`.  This
file is located in the `src` directory of this repository.  When building
"out of tree" filters, it should be copied to the system header file directory,
usually `/usr/include`.

### API Version

The header file defines the `FDF_FILTER_API_VER` constant (macro), which is
used to verify compatibility between the FDF daemon and any filter module that
it loads.  The API does not currently support backward compatibility, so the
versions must match exactly.

The value of this macro is computed from the MD5 hash of the header file itself,
excepting the value of the `FDF_FILTER_API_VER` macro (and the value of the
`FDF_FILTER_CTOR` macro, which is also derived from the hash).  As a result,
**any** changes to the header, including changes to formatting and comments,
will change the value of the API version.  Because the API version must match
exactly, this will require all filter modules to be rebuilt with the new API
version.

### Module Registration

When a filter module is loaded by the daemon, it must register itself by calling
the `fdf_filter_register()` API.

```C
struct fdf_filter_info {
	uint64_t		api_ver;
	fdf_filter_init_fn	init_fn;
	fdf_filter_match_fn	match_fn;
	fdf_filter_cleanup_fn	cleanup_fn;
};

__attribute__((nonnull))
void fdf_filter_register(const struct fdf_filter_info *info);
```

`api_ver` member must be set to `FDF_FILTER_API_VER`.  `init_fn`, `match_fn`,
and `cleanup_fn` are pointers to filter functions that `fdfd` will call at
different times in the module's lifetime.

* The [initialization function](#initialization-function) (`init_fn`) will be
  called once for **each instance** of the filter module when the instance is
  created.  It is optional (may be `NULL`) for filter modules that do not accept
  any parameters.

* The [match function](#match-function) (`match_fn`) is required.  It will be
  called for each packet received by a [listener](../README.md#listeners) whose
  [match](../README.md#match) includes an instance of the filter module in its
  filter chain (unless a filter instance earlier in the chain stops filter
  execution by returning [`FDF_FILTER_PASS_NOW`](#return-value-1) or
  [`FDF_FILTER_DROP_NOW`](#return-value-1)).

* The [cleanup function](#cleanup-function) (`cleanup_fn`) is optional.  It will
  be called once for **each instance** of the filter module when the FDF daemon
  is shutting down cleanly.

`fdf_filter_register()` should be called from a constructor function, which will
automatically be called when the filter module is loaded.

```C
static struct fdf_filter_info foo_info {
	.api_ver	= FDF_FILTER_API_VER,
	.init_fn	= foo_init,
	.match_fn	= foo_match,
	.cleanup_fn	= foo_cleanup
};

__attribute__((constructor))
static void foo_ctor(void)
{
	fdf_filter_register(&foo_info);
}
```

The header file defines a macro that eliminates the need for this boilerplate
code.  The macro should be used in most cases.

```C
FDF_FILTER(foo_init, foo_match, foo_cleanup);
```

### Initialization Function

The initialization function is used to perform any setup required by an instance
of a filter module, which may include "global" setup required by the module
itself.  It must conform to the following type definition.

```C
typedef _Bool (*fdf_filter_init_fn)(uintptr_t handle,
				    int argc, const char *const argv[]);
```

#### Arguments

* `handle` &mdash; An opaque value that identifies the filter instance.  It must
  be passed back to any [FDF filter API functions](#filter-api-functions) called
  from the filter module.

* `argc` &mdash; The number of non-`NULL` members of `argv`.  (`argv[argc]` is
  always `NULL`.)  The minimum value of `argc` is `2`, because the name of the
  filter instance and the path of the filter module file are always present.

* `argv` &mdash; A pointer to a `NULL`-terminated array of character pointers.
  Each member of the array (other than the terminating `NULL` member) points to
  a C string that holds the name of the filter instance, the path used to load
  the filter module, or a filter instance parameter.

  * `argv[0]` points to the name of the filter instance.
  * `argv[1]` points to the path of the filter module file.
  * `argv[2]` through `argv[argc - 1]` point to the filter instance parameters,
    if any.

> **NOTE:** Unlike the `argv` argument to C's `main()` function, the array
> itself and the strings to which its members are all `const` typed.

#### Return Value

The initialization function should return `1` to indicate successful
initialization or `0` if an error occured.

#### Example

```C
static _Bool foo_init(const uintptr_t handle,
		      const int argc __attribute__((unused)),
		      const char *const *const argv)
{
	fdf_filter_log(handle, LOG_DEBUG, "Instance name = %s", argv[0]);
	return 1;
}
```

### Cleanup Function

The cleanup function is used to free any resources (memory allocations, open
file descriptors, etc.) that were acquired by a filter instance, including any
"global" resources that are shared between instances.  It must conform to the
following definition.

```C
typedef void (*fdf_filter_cleanup_fn)(uintptr_t handle);
```

#### Arguments

* `handle` &mdash; An opaque value that identifies the filter instance.  It must
  be passed back to any [FDF filter API functions](#filter-api-functions) called
  from the filter module.

#### Example

```C
static void foo_cleanup(const uintptr_t handle)
{
	fdf_filter_log(handle, LOG_DEBUG, "All done");
}
```

### Match Function

The match function is the workhorse of any filter module.  It is called each
time that a packet is received by a [listener](../README.md#listeners) whose
[match](../README.md#match) includes an instance of the filter module (unless a
filter instance earlier in the chain stops filter execution by returning
`FDF_FILTER_PASS_NOW`(#match-function) or `FDF_FILTER_DROP_NOW`).

The match function should parse the packet payload (if necessary), determine if
the packet should be passed or dropped, and perform any other actions that are
required.  For example:

* In stateful mode, the [multicast DNS filter](mdns-filter.md) adds information
  about any queries that it forwards to a global data structure.  This data
  structure is used to determine if any response packets that it receives should
  be forwarded.

* The [IP set filter](ipset-filter.md) adds the source address and source port
  of any packets that it processes to a kernel IP set.

The match function must conform to the following (rather ugly) definition.

```C
typedef
uint8_t (*fdf_filter_match_fn)(uintptr_t handle,
			       const struct sockaddr_storage *restrict src,
			       const struct sockaddr_storage *restrict dest,
			       const void *restrict pkt, size_t pkt_size,
			       uintptr_t in_netif, uintptr_t *fwd_netif_out);
```

#### Arguments

* `handle` &mdash; An opaque value that identifies the filter instance.  It must
  be passed back to any [FDF filter API functions](#filter-api-functions) called
  from the filter module.

* `src` &mdash; The source address (IP address and UDP port number) of the
  packet.

* `dest` &mdash; The destination address (broadcast or multicast IP address and
  UDP port number) of the packet.

* `pkt` &mdash; The packet payload (not including the IP and UDP headers).

* `pkt_size` &mdash; The size (in octets) of the packet payload.

* `in_netif` &mdash; An opaque value that identifies the network interface on
  which the packet was received.

* `fwd_netif_out` &mdash; An output pointer that can be used to set the
  network interface to which a packet will be forwarded.  The value written via
  the pointer must have previously been received in the `in_netif` argument.

  It is an error for a filter instance to set a forward interface that is not
  valid for the listener that received the packet.  It is also an error for
  more than one filter instance in a [chain](../README.md#filter-chaining) to
  set the forward interface.

#### Return Value

The match function must return one of the following values.

* `FDF_FILTER_PASS` &mdash; Forward the packet if this is the last filter
  instance in the listener's filter chain.  If it is not last in the chain, the
  result of a subsequent filter will be dispositive.

* `FDF_FILTER_DROP` &mdash; Drop the packet if this is the last filter
  instance in the listener's filter chain.  If it is not last in the chain, the
  result of a subsequent filter will be dispositive.

* `FDF_FILTER_PASS_FORCE` &mdash; Forward the packet, unless a subsequent filter
  instance returns `FDF_FILTER_DROP_FORCE` or `FDF_FILTER_DROP_NOW`.

* `FDF_FILTER_DROP_FORCE` &mdash; Drop the packet, unless a subsequent filter
  instance returns `FDF_FILTER_PASS_FORCE` or `FDF_FILTER_PASS_NOW`.

* `FDF_FILTER_PASS_NOW` &mdash; Forward the packet immediately.  Ignore any
  subsequent filter instances in the listener's filter chain.

* `FDF_FILTER_DROP_NOW` &mdash; Drop the packet immediately.  Ignore any
  subsequent filter instances in the listener's filter chain.

#### Example

```C
static uint8_t foo_match(const uintptr_t handle,
			 const struct sockaddr_storage *restrict const src
							__attribute__((unused)),
			 const struct sockaddr_storage *restrict const dest
							__attribute__((unused)),
			 const void *restrict const pkt __attribute__((unused)),
			 const size_t pkt_size __attribute__((unused)),
			 const uintptr_t in_netif __attribute__((unused)),
			 uintptr_t *const fwd_netif_out __attribute__((unused)))
{
	/* Drop 10% of the packets */
	if (rand() % 100 < 10) {
		fdf_filter_log(handle, LOG_INFO, "Dropping unlucky packet");
		return FDF_FILTER_DROP;
	}
	else {
		fdf_filter_log(handle, LOG_DEBUG, "Passing packet");
		return FDF_FILTER_PASS;
	}
}
```

### Helper Functions

The FDF daemon provides a number of helper functions that filter modules may
call.

#### `fdf_filter_log()`

#### `fdf_filter_sock_addr()`

#### `fdf_filter_netif_name()`

#### `fdf_filter_set_data()`

#### `fdf_filter_get_data()`

## Building a Filter Module

## Installing and Using a Filter Module
