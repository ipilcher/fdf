# FDF Filter API

&copy; 2022 Ian Pilcher <<arequipeno@gmail.com>>

* [**Introduction**](#introduction)
* [**Filter API Header**](#filter-api-header)
  * [API Version](#api-version)
  * [Module Registration](#module-registration)
  * [Initialization Function](#initialization-function)
  * [Cleanup Function](#cleanup-function)
  * [Match Function](#match-function)
  * [Helper APIs](#helper-apis)
    * [`fdf_filter_log()`](#fdf_filter_log)
    * [`fdf_filter_sock_addr()`](#fdf_filter_sock_addr)
    * [`fdf_filter_netif_name()`](#fdf_filter_netif_name)
    * [`fdf_filter_set_data()`](#fdf_filter_set_data)
    * [`fdf_filter_get_data()`](#fdf_filter_get_data)
    * [`FDF_FILTER_PKT_AS()`](#fdf_filter_pkt_as)
* [**Building, Installing, and Using a Filter Module**](#building-installing-and-using-a-filter-module)
* [**Filter Development Best Practices**](#filter-development-best-practices)

## Introduction

FDF filters are dynamically loaded modules that extend the functionality of the
service.  FDF includes two filters &mdash; the
[multicast DNS filter](mdns-filter.md) and the [IP set filter](ipset-filter.md),
but additional filters can be created using the APIs described in this document.

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
**any** changes to the header, including changes to formatting or comments,
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

`api_ver` must be set to `FDF_FILTER_API_VER`.  `init_fn`, `match_fn`,
and `cleanup_fn` are pointers to filter functions that `fdfd` will call at
different times in the module's lifetime.

* The [initialization function](#initialization-function) (`init_fn`) will be
  called once for **each instance** of the filter module when that instance is
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
[`FDF_FILTER_PASS_NOW`](#return-value-1) or
[`FDF_FILTER_DROP_NOW`](#return-value-1)).

The match function should parse the packet payload (if necessary), determine
whether the packet should be passed or dropped, and perform any other actions
that are required.

Examples of other actions include:

* In stateful mode, the [multicast DNS filter](mdns-filter.md) adds information
  about any queries that it forwards to a global data structure.  When an mDNS
  response it received, this data structure is used to determine the network to
  which the response should be forwarded (if any).

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

* `pkt` &mdash; The packet payload (not including the IP and UDP headers).  See
  [`FDF_FILTER_PKT_AS()`](#fdf_filter_pkt_as).

* `pkt_size` &mdash; The size (in bytes) of the packet payload.

* `in_netif` &mdash; An opaque value that identifies the network interface on
  which the packet was received.

* `fwd_netif_out` &mdash; An output pointer that can be used to set the
  network interface to which a packet will be forwarded.  The value written via
  the pointer must have previously been passed in the `in_netif` argument.

  It is an error for a filter instance to set a forward interface that is not
  valid for the listener that received the packet.  It is also an error for
  more than one filter instance in a [chain](../README.md#filter-chaining) to
  set the forward interface.

#### Return Value

The match function must return one of the following values.

* `FDF_FILTER_PASS` &mdash; Forward the packet if this is the last filter
  instance in the listener's filter chain.  If it is not last in the chain, the
  disposition of the packet will be determined by the result(s) of the
  subsequent filter(s).

* `FDF_FILTER_DROP` &mdash; Drop the packet if this is the last filter
  instance in the listener's filter chain.  If it is not last in the chain, the
  disposition of the packet will be determined by the result(s) of the
  subsequent filter(s).

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

### Helper APIS

The FDF daemon provides a number of helper APIs that filter modules may use.

#### `fdf_filter_log()`

```C
__attribute__((format(printf, 3, 4), nonnull))
void fdf_filter_log(uintptr_t handle, int priority,
		    const char *restrict format, ...);
```

Log a message via the FDF daemon.  The message may be suppressed in some
circumstances.

* If `priority` is `LOG_DEBUG` and the daemon was not executed with the `-d` (or
  `--debug`) option.

* If `fdf_filter_log()` is called from the filter module's match
  function (or a function called from the match function, etc.),
  `priority` is `LOG_INFO` or `LOG_DEBUG`, and the daemon was not executed with
  the `-p` (or `--pktlog`) option.  (**Both** `-d` and `-p` must be specified in
  order to see `LOG_DEBUG` messages issued from within a filter module's match
  function.)

##### Arguments

* `handle` &mdash; The `handle` value that was passed to the module's
  initialization, match, or cleanup function.

* `priority` &mdash; A
  [`syslog(3)`](https://man7.org/linux/man-pages/man3/syslog.3.html)-style
  constant that identifies the severity of the message &mdash; `LOG_DEBUG`,
  `LOG_INFO`, ..., `LOG_EMERG`.

* `format` &mdash; A
  [`printf(3)`](https://man7.org/linux/man-pages/man3/printf.3.html)-style
  format string for the message.  (No trailing newline is required; the daemon
  will add it to the final message if needed.)

* `...` &mdash; Additional `printf(3)`-style arguments (if any) that match the
  format string.

#### `fdf_filter_sock_addr()`

```C
__attribute__((nonnull))
const char *fdf_filter_sock_addr(uintptr_t handle,
				 const struct sockaddr_storage *restrict addr,
				 char *restrict dst, size_t size);
```

Converts the IPv4 or IPv6 socket address in `addr` to a textual representation
(C string) in `dst`.  IPv4 socket addresses are formatted in standard dotted
decimal format, followed by a colon and the decimal port number &mdash; e.g.
`224.0.0.251:5353`; IPv6 socket addresses place the canonical form of the IPv6
address within square brackets, followed by a colon and the decimal port number
&mdash; e.g. `[ff02::fb]:5353`.

> **NOTE:** FDF does not currently support IPv6.

##### Arguments

* `handle` &mdash; The `handle` value that was passed to the module's
  initialization, match, or cleanup function.

* `addr` &mdash; The address to be formatted.

* `dst` &mdash; The buffer into which the formatted address will be placed.  The
  buffer size must be at least `FDF_FILTER_SA4_LEN` (if formatting an IPv4
  socket address) or `FDF_FILTER_SA6_LEN` (if formatting an IPv6 socket
  address).

* `size` &mdash; The size of the destination buffer.

##### Return Value

Returns `dst`.

#### `fdf_filter_netif_name()`

```C
const char *fdf_filter_netif_name(uintptr_t handle, uintptr_t netif);
```

Retrieves the name of the network interface identified by `netif`.

##### Arguments

* `handle` &mdash; The `handle` value that was passed to the module's
  initialization, match, or cleanup function.

* `netif` &mdash; An opaque network interface identifier that was passed in the
  match function's `in_netif` argument.

##### Return Value

A pointer to a C string that contains the name of the network interface.

#### `fdf_filter_set_data()`

```C
union fdf_filter_data {
	void		*p;
	uintptr_t	u;
	intptr_t	i;
	_Bool		b;
};

void fdf_filter_set_data(uintptr_t handle, union fdf_filter_data data);
```

Associates arbitrary data with a filter instance.  The data can be retrieved
with [`fdf_filter_get_data()`](#fdf_filter_get_data).

##### Arguments

* `handle` &mdash; The `handle` value that was passed to the module's
  initialization, match, or cleanup function.

* `data` &mdash; The data to be associated with the filter instance.

#### `fdf_filter_get_data()`

```C
union fdf_filter_data fdf_filter_get_data(uintptr_t handle);
```

Retrieves data that that was previously associated with the filter instance by
[`fdf_filter_set_data()`](#fdf_filter_set_data).

##### Arguments

* `handle` &mdash; The `handle` value that was passed to the module's
  initialization, match, or cleanup function.

##### Return Value

The data that was most recently associated with the filter instance.

#### `FDF_FILTER_PKT_AS()`

```C
#define FDF_FILTER_PKT_AS(type, pkt)					\
	({								\
		_Static_assert(__alignof__(type) <= 4,			\
			       "alignment of " #type " too large");	\
		(const type *)pkt;					\
	})
```

Casts `pkt` (the packet payload that was passed to the match function) as a
pointer to `const type`.  Issues a compile-time error if `type`'s alignment is
too large.

For example, the code below will cause a compile-time error on 64-bit platforms,
because the alignment of `struct my_pkt` is too large.

```C
struct my_pkt {
	uint64_t	magic_number;  /* 8-byte alignment on 64-bit */
	uint8_t		data[];
};

/* Called from initialization function */
static void check_pkt(const void *restrict const pkt)
{
	struct my_pkt *p;

	p = FDF_FILTER_PKT_AS(struct my_pkt, pkt);
}
```

##### Arguments

* `type` &mdash; The C type that will be used to process the packet payload.

* `pkt` &mdash; The packet payload (the [match function's](#match-function)
  `pkt` argument).

##### Return Value

A pointer to the packet payload, cast to a pointer to `const type`.

## Building, Installing, and Using a Filter Module

Consider the following simple filter (`foo.c`), which combines the examples
above.

```C
#include <fdf-filter.h>
#include <syslog.h>

static _Bool foo_init(const uintptr_t handle,
		      const int argc __attribute__((unused)),
		      const char *const *const argv)
{
	fdf_filter_log(handle, LOG_DEBUG, "Instance name = %s", argv[0]);
	return 1;
}

static void foo_cleanup(const uintptr_t handle)
{
	fdf_filter_log(handle, LOG_DEBUG, "All done");
}

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

FDF_FILTER(foo_init, foo_match, foo_cleanup);
```

To build the module, simply compile it with the `-shared` and `-fPIC` options.
For example:

```
$ gcc -std=gnu99 -O3 -Wall -Wextra -Wcast-align -shared -fPIC -o foo.so foo.c
```

> **NOTE:** See the note [here](../README.md#compiling) about the `-std=gnu99`
and `-Wcast-align` options.

The FDF daemon does not search any particular directory (other than
the system's standard library directories) for filter modules; the paths to all
filter module files must be specified in the configuration.  Thus, there is no
particular location to which filter modules must be installed.  The recommended
practice, however, is to place all filter modules in a single directory:

* `/usr/local/lib/fdf-filters` or `/usr/local/lib64/fdf-filters` if the module
  is manually installed, or

* `/usr/lib/fdf-filters` or `/usr/lib64/fdf-filters` if the module is installed
  with a system package manager.

The filter module can be used by including it in the FDF configuration.  For
example:

```json
	"filters": {
		"foo": {
			"file": "/usr/local/lib64/fdf-filters/foo.so"
		}
	}
```

## Filter Development Best Practices

* Don't directly assign (or cast) the match function's `pkt` argument to a
  typed pointer.  Use the [`FDF_FILTER_PKT_AS()`](#fdf_filter_pkt_as) macro.

* Use the [`fdf_filter_log()`](#fdf_filter_log) function for any error or
  informational messages.

* Ensure that the cleanup function frees all resources that the filter module
  acquires during its lifetime, including any module-wide resources that are
  shared between instances.  The FDF daemon itselt has no known memory or file
  descriptor leaks, so tools such as [`valgrind`](https://valgrind.org/) can be
  used to check for resource leaks.
