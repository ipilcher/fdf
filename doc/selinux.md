# FDF SELinux Support

* [**Installation**](#installation)
* [**Configuration**](#configuration)
  * [Files](#files)
  * [Listener Ports](#listener-ports)
    * [Unreserved ports](#unreserved-ports)
    * [Reserved ports](#reserved-ports)

&copy; 2023 Ian Pilcher <<arequipeno@gmail.com>>

## Installation

Building the SELinux policy module requires that the SELinux policy development
files are installed on the build system.  On Fedora and RHEL-like systems these
files are in the `selinux-policy-devel` package.

From the `selinux` directory within this repository, build the policy module.
(Ignore any warnings about duplicate macro definitions.)

```
$ make -f /usr/share/selinux/devel/Makefile
...
Compiling targeted fdf module
Creating targeted fdf.pp policy package
rm tmp/fdf.mod tmp/fdf.mod.fc
```

If necessary, copy the policy module (`fdf.pp`) to the system on which FDF will
run and install it.

```
# semodule -i fdf.pp
```

## Configuration

Set the SELinux context of the files and network ports that FDF will use.

### Files

Adjust the paths in the below commands as needed.

```
# chcon -t fdf_exec_t /usr/local/bin/fdfd
# chcon -R -t fdf_lib_t /usr/local/lib64/fdf-filters
# chcon -t fdf_etc_t /etc/fdf-config.json
```

## Listener Ports

By default, the policy module does not allow FDF to listen on any network ports;
each listener port must be specifically enabled.  The mechanism for doing so
depends on whether the port already has an SELinux context assigned.

SELinux port contexts can be listed with the `semanage` command.

```
# semanage port -l
SELinux Port Type              Proto    Port Number

afs3_callback_port_t           tcp      7001
afs3_callback_port_t           udp      7001
afs_bos_port_t                 udp      7007
...
zookeeper_election_port_t      tcp      3888
zookeeper_leader_port_t        tcp      2888
zope_port_t                    tcp      8021
```

Note however that this command displays contiguous port ranges in a hyphenated
format (e.g. `5985-5999, 5900-5983`).  It may also display two different
contexts for a port in some circumstances, only one of which is correct.  (See
[this mailing list thread](https://lore.kernel.org/selinux/CAEjxPJ7mu39hGzNx8HN0HAm_h1KpGcrryQW5qHiOYEhf76p-OQ@mail.gmail.com/T/#m6002d98166286334731ac4d3c9c2d9b65e66fad8).)

Ultimately, the best way to determine the context of a port is to attempt to
use it and check the AVC message in the event that FDF is not able to bind
to the port.

### Unreserved ports

Ports that do not have an SELinux context assigned are considered "unreserved."
If FDF attempts to bind to such a port, the audit log will contain a message
similar to this.

```
type=AVC msg=audit(1690737075.974:2609): avc:  denied  { name_bind } for
	pid=6990 comm="fdfd" src=3483 scontext=system_u:system_r:fdf_t:s0
	tcontext=system_u:object_r:unreserved_port_t:s0 tclass=udp_socket
	permissive=0
```

Note the type of the target context &mdash;
`tcontext=system_u:object_r:unreserved_port_t:s0`.

To enable FDF to bind to an unreserved port, simply assign the `fdf_port_t` type
to that port.  For example:

```
# semanage port -a -t fdf_port_t -p udp 3483
```

> **NOTE:** If the port already has a context assigned, an error message will be
> printed.
>
> ```
> # semanage port -a -t fdf_port_t -p udp 1900
> ValueError: Port udp/1900 already defined
> ```

### Reserved ports

If FDF attempts to bind to a port that already has an SELinux context, the
denial message in the audit log will show the port context.

```
type=AVC msg=audit(1690746451.947:3916): avc:  denied  { name_bind } for
	pid=7812 comm="fdfd" src=1900 scontext=system_u:system_r:fdf_t:s0
	tcontext=system_u:object_r:ssdp_port_t:s0 tclass=udp_socket permissive=0
```

In this case, UDP port 1900 is already labeled as `ssdp_port_t`.

This policy provides SELinux booleans that, when enabled, allow FDF to bind to
specific port types.  Currently, two such booleans are provided.

* `fdf_listen_mdns` allows FDF to bind to the
  [multicast DNS](https://en.wikipedia.org/wiki/Multicast_DNS) port (UDP port
  5353).

* `fdf_listen_ssdp` allows FDF to bind to the
  [Simple Service Discovery Protocol](https://en.wikipedia.org/wiki/Simple_Service_Discovery_Protocol)
  port (UDP port 1900).

To enable FDF to listen to traffic on one of these ports, simply enable the
corresponding boolean.

```
# setsebool -P fdf_listen_ssdp on
```

If you need to enable FDF to listen on a port with an existing SELinux context
that is not covered by a policy boolean, please create an issue
[here](https://github.com/ipilcher/fdf/issues).

As a temporary workaround, it is possible to use `semanage` to change the
context of a port to `fdf_port_t`, but it is important to be aware of the
effects of doing this.

* The output of `semanage port -l` will be misleading.  For example.

  ```
  # semanage port -l | grep 'udp      177'
  xdmcp_port_t                   udp      177

  # semanage port -m -t fdf_port_t -p udp 177

  # semanage port -l | grep 'udp      177'
  fdf_port_t                     udp      177, 3483
  xdmcp_port_t                   udp      177
  ```

  This appears to show that UDP port 177 is labeled as **both** `fdf_port_t` and
  `xdmcp_port_t`, but this is not the case.  The local customization
  (`fdf_port_t`) overrides the context defined in the policy (`xdmcp_port_t`).

* Because the context of UDP port 177 has been changed, any existing SELinux
  rules that allow applications to access this port will no longer work.  If any
  such applications are running on the system, they will either fail to start or
  not work correctly.

When no longer needed, the local override should be removed.

```
# semanage port -d -p udp 177

# semanage port -l | grep 'udp      177'
xdmcp_port_t                   udp      177
```
