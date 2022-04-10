# FDF on OpenWrt

&copy; 2022 Ian Pilcher <<arequipeno@gmail.com>>

* [**Introduction**](#introduction)
* [**Step 1: Prepare the Build System**](#step-1-prepare-the-build-system)
* [**Step 2: Prepare the Build Environment**](#step-2-prepare-the-build-environment)
  * [Step 2a: Download the OpenWrt Sources](#step-2a-download-the-openwrt-sources)
  * [Step 2b: Configure the OpenWrt Build](#step-2b-download-the-openwrt-build)
    * [Select the Target Profile](#select-the-target-profile)
    * [Enable the `libmnl` Library](#enable-the-libmnl-library)
  * [Step 2c: Built OpenWrt](#step-2c-build-openwrt)
* [**Step 3: Build `libsavl` and FDF**](#step-3-build-libsavl-and-fdf)
  * [Step 3a: Paths and Variables](#step-3a-paths-and-variables)
    * [Build Directory &mdash; `BUILD_DIR`](#build-directory--build_dir)
    * [Staging Directory &mdash; `STAGING_DIR`](#staging-directory--staging_dir)
    * [Cross Compiler Executable &mdash; `XGCC`](#cross-compiler-executable--xgcc)
    * [Library Directory &mdash; `LIB_DIR`](#library-directory--lib_dir)
    * [Header Directory &mdash; `HEADER_DIR`](#header-directory--header_dir)
  * [Step 3b: Build and Install `libsavl`](#step-3b-build-and-install-libsavl)
    * [Download `libsavl`](#download-libsavl)
    * [Determine the Library Version and soname](#determine-the-library-version-and-soname)
    * [Build the Library](#build-the-library)
    * [Install the Library](#install-the-library)
  * [Step 3c: Build FDF](#step-3c-build-fdf)
    * [Download FDF](#download-fdf)
    * [Build the Daemon](#build-the-daemon)
    * [Build the Included Filters](#build-the-included-filters)
* [**Step 4: Install `libsavl` and FDF**](#step-4-install-libsavl-and-fdf)
  * [Step 4a: Transfer Files](#step-4a-transfer-files)
  * [Step 4b: Install `libsavl`](#step-4b-install-libsavl)
  * [Step 4c: Install Other Dependencies](#step-4c-install-other-dependencies)
  * [Step 4d: Install FDF](#step-4d-install-fdf)
  * [Step 4e: Install the Initialization Scripts](#step-4e-install-the-initialization-scripts)
  * [Step 4f: Configuration Files](#step-4f-configuration-files)
* [**Step 5: Configure the Device Network and Firewall**](step-5-configure-the-device-network-and-firewall)
* [**Step 6: Final Steps**](#step-6-final-steps)
  * [Step 6a: Run FDF Manually](#step-6a-run-fdf-manually)
  * [Step 6b: Run FDF as a Service](#step-6b-run-fdf-as-a-service)
  * [Step 6c: Enable the Services and Reboot](#step-6c-enable-the-services-and-reboot)

## Introduction

[OpenWrt](https://openwrt.org) is a popular Linux-based alternative operating
system for residential routers.  As such, it is an obvious target for FDF.  This
document provides build and installation instructions for OpenWrt.

> **NOTES:**
>
> * Support for OpenWrt is **experimental**.  I personally use my OpenWrt device
>   only as a wireless access point, not as a router, so I don't run FDF on
>   OpenWrt.  (I run FDF on my firewall/router, which is an x86-based
>   [Protectli](https://protectli.com/) Vault running CentOS 7.)
>
> * Building software for OpenWrt is a somewhat complex process.  The software
>   must be [cross compiled](https://en.wikipedia.org/wiki/Cross_compiler),
>   because the target devices are not usually powerful enough for software
>   development (even if you did want to install the required development tools,
>   library headers, etc., on your router).
>
>   Furthermore, the easiest way to
>   set up a cross compilation environment is to go through the process of
>   building OpenWrt itself.  As the
>   [OpenWrt build documentation](https://openwrt.org/docs/guide-developer/toolchain/buildsystem_essentials#description)
>   states, "The process of creating a cross compiler can be tricky. It's not
>   something that's regularly attempted and so the there's a certain amount of
>   mystery and black magic associated with it."  The process is also fairly
>   resource-intensive.  I recommend placing the build directory on a file
>   system with at least 15 GB free.  If possible, use a system with at least 4
>   CPU cores and 8 GB of memory available.

## Step 1: Prepare the Build System

Follow the instructions
[here](https://openwrt.org/docs/guide-developer/toolchain/install-buildsystem)
to prepare your system.

On my Fedora system, for example:

```
$ sudo dnf --setopt install_weak_deps=False --skip-broken install \
	bash-completion bzip2 gcc gcc-c++ git make ncurses-devel patch \
	rsync tar unzip wget which diffutils python2 python3 perl-base \
	perl-Data-Dumper perl-File-Compare perl-File-Copy perl-FindBin \
	perl-Thread-Queue
Last metadata expiration check: 1:27:33 ago on Mon 28 Mar 2022 01:08:36 PM CDT.
Package bash-completion-1:2.11-3.fc35.noarch is already installed.
Package bzip2-1.0.8-9.fc35.x86_64 is already installed.
⋮
Package perl-Thread-Queue-3.14-478.fc35.noarch is already installed.
Dependencies resolved.
Nothing to do.
Complete!
```

## Step 2: Prepare the Build Environment

##### References

* [Toolchain](https://openwrt.org/docs/guide-developer/toolchain/start)
* [Build system usage](https://openwrt.org/docs/guide-developer/toolchain/use-buildsystem)

### Step 2a: Download the OpenWrt Sources

Download the OpenWrt source.  Change to the source repository's top-level
directory (the "build directory"), and checkout the tag that corresponds to the
OpenWrt version that your device is running.

> **NOTE:**  The examples below are all written for my personal device, a
> [TP-Link Archer C7 AC1750](https://openwrt.org/toh/tp-link/archer_c7) v2
> running OpenWrt 21.02.2.

```
$ git clone https://git.openwrt.org/openwrt/openwrt.git
Cloning into 'openwrt'...
remote: Enumerating objects: 7248, done.
remote: Counting objects: 100% (7248/7248), done.
remote: Compressing objects: 100% (5439/5439), done.
remote: Total 595885 (delta 4025), reused 2676 (delta 1505), pack-reused 588637
Receiving objects: 100% (595885/595885), 175.36 MiB | 11.61 MiB/s, done.
Resolving deltas: 100% (415585/415585), done.

$ cd openwrt

$ git tag
⋮
v21.02.0-rc4
v21.02.1
v21.02.2

$ git checkout v21.02.2
HEAD is now at 30e2782e06 OpenWrt v21.02.2: adjust config defaults
```

Update the "[feeds](https://openwrt.org/docs/guide-developer/feeds)."  Both of
these commands will generate a lot of output, so check the exit codes.

```
$ ./scripts/feeds update -a
Updating feed 'packages' from 'https://git.openwrt.org/feed/packages.git^b0ccc356900f6e1e1dc613d0ea980d5572f553dd' ...
Cloning into './feeds/packages'...
remote: Enumerating objects: 160727, done.
⋮
Create index file './feeds/telephony.index'
Collecting package info: done
Collecting target info: done

$ echo $?
0

$ ./scripts/feeds install -a
Collecting package info: done
Collecting target info: done
WARNING: Makefile 'package/utils/busybox/Makefile' has a dependency on 'libpam', which does not exist
⋮
Installing package 'siproxd' from telephony
Installing package 'sngrep' from telephony
Installing package 'yate' from telephony

$ echo $?
0
```

### Step 2b: Configure the OpenWrt Build

Follow the instructions
[here](https://openwrt.org/docs/guide-developer/toolchain/use-buildsystem#using_official_build_config)
to download the official build config for your device.

```
$ wget https://downloads.openwrt.org/releases/21.02.1/targets/ath79/generic/config.buildinfo -O .config
--2022-03-28 14:30:52--  https://downloads.openwrt.org/releases/21.02.1/targets/ath79/generic/config.buildinfo
Resolving downloads.openwrt.org (downloads.openwrt.org)... 168.119.138.211, 2a01:4f8:251:321::2
Connecting to downloads.openwrt.org (downloads.openwrt.org)|168.119.138.211|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 39799 (39K) [text/plain]
Saving to: ‘.config’

.config                  100%[==================================>]  38.87K  --.-KB/s    in 0.004s

2022-03-28 14:30:53 (10.3 MB/s) - ‘.config’ saved [39799/39799]
```

Run `make menuconfig`.  This will bring up an
[ncurses](https://en.wikipedia.org/wiki/Ncurses)-based interface that can be
used to modify the OpenWrt configuration.

#### Select the Target Profile

As noted in
[Using the official build config](https://openwrt.org/docs/guide-developer/toolchain/use-buildsystem#using_official_build_config),
the build config does not specify a target profile.  Instead, it enables **all**
of the target profiles for a given target and subtarget.  Presumably, this
allows the OpenWrt project to create images for multiple similar devices in a
single build, but it unnneccessarily increases the build time and storage
consumption in this situation.

* At the top-level **OpenWrt Configuration** menu, use the arrow keys to
  highlight **Target Profile (Multiple devices)** and press the enter key (`↵`)
  to select the submenu.

* In the **Target Profile** submenu, scroll down to locate your device.
  (Entries are **not** listed in strictly alphabetical order.)

* Highlight the correct device and press `↵` to select it and return to the
  **OpenWrt Configuration** menu.

#### Enable the `libmnl` Library

[`libmnl`](https://www.netfilter.org/projects/libmnl/index.html) is required by
FDF's [IP set filter](ipset-filter.md), but it is not included in OpenWrt images
by default, so it won't normally be built when building OpenWrt.

* At the **OpenWrt Configuration** menu, highlight **Libraries** and press `↵`
  to select it.

* In the **Libraries** submenu, highlight **libmnl** and press `Y` to enable it.

* Press the right arrow key 3 times to highlight `<Save>` and press `↵`.

* Press `↵` again to save the configuration as `.config`.

* Press `↵` one more time to return to the **Libraries** submenu.

* Press `Esc` four times to exit from the configuration tool.

### Step 2c: Build OpenWrt

Determine the number of concurrent jobs to be used during the build process.
For the fastest build, choose a number that is equal to, or slightly greater
than, the number of logical processors (threads) in your system.  Choose a lower
number to reserve some processor capacity for other workloads.  The number of
jobs also impacts memory consumption, so it may be necessary to limit the
number on a memory constrained system with a large number of logical processors.

`nice` and `ionice` can also be used to limit the impact of the OpenWrt build on
the rest of the system.

```
$ make -j18
make[2]: Entering directory '/mnt/scratch/openwrt/scripts/config'
cc -O2   -c -o conf.o conf.c
cc   conf.o confdata.o expr.o lexer.lex.o parser.tab.o preprocess.o symbol.o util.o   -o conf
make[2]: Leaving directory '/mnt/scratch/openwrt/scripts/config'
time: target/linux/prereq#0.60#0.05#0.65
 make[1] world
⋮
 make[2] package/index
 make[2] json_overview_image_info
 make[2] checksum

$ echo $?
0
```

## Step 3: Build `libsavl` and FDF

### Step 3a: Paths and Variables

##### References

* [Directory structure](https://openwrt.org/docs/guide-developer/toolchain/buildsystem_essentials#directory_structure)

The OpenWrt build process created the cross compiler, tools, and libraries
needed to build FDF (and `libsavl`, upon which it depends).  The files are
located in several different directories, and the paths to those directories are
quite long.  The actual build process is much simpler if some important file and
directory paths are stored in shell variables.

#### Build Directory &mdash; `BUILD_DIR`

All of the paths are located under the top-level directory of the OpenWrt
repository that was created when the repository was cloned in
[step 2a](#step-2a-download-the-openwrt-sources).

Change to the build directory and store its path in a shell variable named
`BUILD_DIR`, for example:

```
$ cd /mnt/scratch/openwrt

$ BUILD_DIR=`pwd`
```

> **NOTE:** `/mnt/scratch/openwrt` is the build directory on my system.

#### Staging Directory &mdash; `STAGING_DIR`

The staging directory contains the cross compiler and other tools that run on
the build host to create binary files compatible with the OpenWrt device.  It
is located at
`${BUILD_DIR}/staging_dir/toolchain-${CPU_ARCH}_gcc-${GCC_VER}_${C_LIB}`, where
`${CPU_ARCH}`, `${GCC_VER}`, and `${C_LIB}` depend on the version of OpenWrt
and the device for which it was built.

For example, my TP-Link Archer C7 AC1750 v2 has a
[MIPS 24Kc](https://openwrt.org/docs/techref/instructionset/mips_24kc)
processor, and OpenWrt 21.02.2 uses GCC 8.4 and the
[musl C library](https://musl.libc.org/).  Therefore, the staging directory is
`${BUILD_DIR}/staging_dir/toolchain-mips_24kc_gcc-8.4.0_musl`.

```
$ ls staging_dir
host     packages               toolchain-_gcc-_
hostpkg  target-mips_24kc_musl  toolchain-mips_24kc_gcc-8.4.0_musl

$ STAGING_DIR=${BUILD_DIR}/staging_dir/toolchain-mips_24kc_gcc-8.4.0_musl
```

Export the `STAGING_DIR` variable, so that it will be visible to the cross
compiler.

```
$ export STAGING_DIR
```

> **NOTE:** The following commands illustrate the difference between a shell
> variable (a variable that has not been exported) and an environment variable.
>
> ```
> $ FOO=bar
>
> $ echo $FOO
> bar
>
> $ bash -c 'echo $FOO'
> ```
>
> This produces no output, because the variable `FOO` is not visible in the
> child shell.  (The single quotes prevent the variable from being expanded by
> the parent shell.)
>
> ```
> $ export FOO
>
> $ bash -c 'echo $FOO'
> bar
> ```
>
> Now, the child shell is able to expand `$FOO`, because the variable is
> visible.

#### Cross Compiler Executable &mdash; `XGCC`

The cross compiler executable is a regular (non-symlink) file in the
`${STAGING_DIR}/bin` directory.  It is the only regular file whose name ends
with `-gcc`.  Store the cross compiler's complete path in a shell variable named
`XGCC`.

```
$ XGCC=`find ${STAGING_DIR}/bin -name '*-gcc' -type f`

$ echo ${XGCC}
/mnt/scratch/openwrt/staging_dir/toolchain-mips_24kc_gcc-8.4.0_musl/bin/mips-openwrt-linux-musl-gcc
```

> **NOTE:**  The output of the `echo` command will begin with your build
> directory path, which may not be `/mnt/scratch/openwrt`.

#### Library Directory &mdash; `LIB_DIR`

The library directory contains shared libraries that were built for the OpenWrt
device by the OpenWrt build process.  It is located at
`${BUILD_DIR}/staging_dir/target-${CPU_ARCH}_${C_LIB}/usr/lib`.  When OpenWrt
21.02.2 (musl C library) is built for my TP-Link Archer C7 AC1750 v2 (MIPS 24Kc
processor), the path is
`${BUILD_DIR}/staging_dir/target-mips_24kc_musl/usr/lib`.

```
$ ls staging_dir
host     packages               toolchain-_gcc-_
hostpkg  target-mips_24kc_musl  toolchain-mips_24kc_gcc-8.4.0_musl

$ ls staging_dir/target-mips_24kc_musl/usr/lib
cmake                        liblucihttp.so             libpcre32.so
libacl.a                     liblucihttp.so.0           libpcre32.so.0
libacl.so                    liblucihttp.so.0.1         libpcre32.so.0.0.12
⋮
liblualib.so                 libpcre16.so.0             pkgconfig
liblua.so                    libpcre16.so.0.2.12        terminfo
liblua.so.5.1.5              libpcre32.a

$ LIB_DIR=${BUILD_DIR}/staging_dir/target-mips_24kc_musl/usr/lib
```

> **NOTE:** The CPU architecture of a binary file can be shown with the `file`
> utility.
>
> ```
> $ file $XGCC
> /mnt/scratch/openwrt/staging_dir/toolchain-mips_24kc_gcc-8.4.0_musl/bin/mips-openwrt-linux-musl-gcc:
> ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux
> -x86-64.so.2, BuildID[sha1]=a770dca0917bdc6a7582414cb91393d6020812ad, for GNU/Linux 3.2.0, with debu
> g_info, not stripped
>
> $ file ${LIB_DIR}/libpcre16.so.0.2.12
> /mnt/scratch/openwrt/staging_dir/target-mips_24kc_musl/usr/lib/libpcre16.so.0.2.12: ELF 32-bit MSB sh
> ared object, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, with debug_info, not stripped
> ```

#### Header Directory &mdash; `HEADER_DIR`

Library header files are located in
`${BUILD_DIR}/staging_dir/target-${CPU_ARCH}_${C_LIB}/usr/include`
(`${BUILD_DIR}/staging_dir/target-mips_24kc_musl/usr/include` for my device.

```
$ HEADER_DIR=`echo ${LIB_DIR} | sed 's/lib$/include/'`

$ echo ${HEADER_DIR}
/mnt/scratch/openwrt/staging_dir/target-mips_24kc_musl/usr/include

$ ls ${HEADER_DIR}
acl               gdbm.h         libubus.h             ncurses.h            term.h
argp.h            gmp.h          libunwind-common.h    ncursesw             ubi-media.h
atmarpd.h         ip6tables.h    libunwind-coredump.h  net                  ubi-user.h
⋮
expat.h           libubi.h       menu.h                swlib.h              zlib.h
form.h            libubi-tiny.h  nbpf.h                sys
fts.h             libubox        ncurses_dll.h         termcap.h
```

### Step 3b: Build and Install `libsavl`

##### References

* [Manually building and installing](https://github.com/ipilcher/libsavl#manually-building-and-installing)

[`libsavl`](https://github.com/ipilcher/libsavl) provides a lightweight
[AVL tree](https://en.wikipedia.org/wiki/AVL_tree) implementation, which FDF
uses for various data structures.

#### Download `libsavl`

From the build directory, clone the repository and change to its top-level
directory.

```
$ cd ${BUILD_DIR}

$ git clone https://github.com/ipilcher/libsavl.git
Cloning into 'libsavl'...
remote: Enumerating objects: 79, done.
remote: Counting objects: 100% (75/75), done.
remote: Compressing objects: 100% (52/52), done.
remote: Total 79 (delta 34), reused 60 (delta 20), pack-reused 4
Receiving objects: 100% (79/79), 64.97 KiB | 1.33 MiB/s, done.
Resolving deltas: 100% (34/34), done.

$ cd libsavl
```

#### Determine the Library Version and [soname](https://en.wikipedia.org/wiki/Soname)

The full library version and can be determined from the latest tag in the
repository.  For example:

```
$ git describe --tags --abbrev=0
v0.7.1
```

In this case, the full library version is `0.7.1` (the numeric portion of the
name of the Git tag).  The shared object version is `0.7` (the first 2 two
elements of the library version), and the soname is `libsavl.so.0.7`.

#### Build the Library

Use the cross compiler to build the library.  Use the full library version in
the name of the output file (e.g., `-o libsavl.so.0.7.1`).

```
$ $XGCC -O3 -Wall -Wextra -Wcast-align -shared -fPIC -I${HEADER_DIR} \
	-o libsavl.so.0.7.1 savl.c -Wl,-soname=libsavl.so.0.7

$ file libsavl.so.0.7.1
libsavl.so.0.7.1: ELF 32-bit MSB shared object, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically link
ed, with debug_info, not stripped

$ objdump -p libsavl.so.0.7.1 | grep SONAME
  SONAME               libsavl.so.0.7
```

#### Install the Library

The library (and its header file) must be installed before it can be used to
build FDF.  First, copy the library to the library directory and create two
symbolic links, one that matches the library's so name and one that is
unversioned.

```
$ cp libsavl.so.0.7.1 ${LIB_DIR}

$ ln -s libsavl.so.0.7.1 ${LIB_DIR}/libsavl.so.0.7

$ ln -s libsavl.so.0.7.1 ${LIB_DIR}/libsavl.so

$ ls -l ${LIB_DIR}/libsavl* | awk '{ print $9 " " $10 " " $11 }'
/mnt/scratch/openwrt/staging_dir/target-mips_24kc_musl/usr/lib/libsavl.so -> libsavl.so.0.7.1
/mnt/scratch/openwrt/staging_dir/target-mips_24kc_musl/usr/lib/libsavl.so.0.7 -> libsavl.so.0.7.1
/mnt/scratch/openwrt/staging_dir/target-mips_24kc_musl/usr/lib/libsavl.so.0.7.1
```

Second, copy the header file to the header directory.

```
$ cp savl.h ${HEADER_DIR}

$ ls ${HEADER_DIR}/savl*
/mnt/scratch/openwrt/staging_dir/target-mips_24kc_musl/usr/include/savl.h
```

### Step 3c: Build FDF

##### References

* [Compiling](../README.md#compiling)

#### Download FDF

Return to the build directory, download the FDF repository, and change to its
`src` subdirectory.

```
$ cd ${BUILD_DIR}

$ git clone https://github.com/ipilcher/fdf.git
Cloning into 'fdf'...
remote: Enumerating objects: 201, done.
remote: Counting objects: 100% (201/201), done.
remote: Compressing objects: 100% (141/141), done.
remote: Total 201 (delta 96), reused 160 (delta 57), pack-reused 0
Receiving objects: 100% (201/201), 89.44 KiB | 1.94 MiB/s, done.
Resolving deltas: 100% (96/96), done.

$ cd fdf/src
```

#### Build the Daemon

Update the API version and use the cross compiler to build the daemon (`fdfd`).

```
$ ./apiver.sh

$ $XGCC -O3 -Wall -Wextra -Wcast-align -o fdfd -I${HEADER_DIR} *.c \
	-L${LIB_DIR} -lsavl -ljson-c -ldl -Wl,--dynamic-list=symlist

$ file fdfd
fdfd: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter
/lib/ld-musl-mips-sf.so.1, with debug_info, not stripped
```

#### Build the Included Filters

Change to the repository's `src/filters` subdirectory and use the cross
compiler to build the included filters.

```
$ cd filters

$ $XGCC -O3 -Wall -Wextra -Wcast-align -shared -fPIC -o mdns.so \
	-I${HEADER_DIR} -I.. mdns.c -L${LIB_DIR} -lsavl

$ $XGCC -O3 -Wall -Wextra -Wcast-align -shared -fPIC -o ipset.so \
	-I${HEADER_DIR} -I.. ipset.c -L${LIB_DIR} -lmnl

$ file *.so
ipset.so: ELF 32-bit MSB shared object, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, with
 debug_info, not stripped
mdns.so:  ELF 32-bit MSB shared object, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, with
 debug_info, not stripped
```

## Step 4: Install `libsavl` and FDF

### Step 4a: Transfer Files

Return to the build directory and copy the required files to the OpenWrt device
(referred to as `${OPENWRT_DEV}` below).

```
$ cd ${BUILD_DIR}

$ scp libsavl/libsavl.so.* fdf/src/fdfd fdf/src/filters/*.so fdf/openwrt/* root@${OPENWRT_DEV}:
root@wap2's password:
libsavl.so.0.7.1                              100%   11KB 227.6KB/s   00:00
fdfd                                          100%   41KB 240.9KB/s   00:00
ipset.so                                      100%   13KB 226.8KB/s   00:00
mdns.so                                       100%   17KB 232.9KB/s   00:00
fdf                                           100%  142    30.8KB/s   00:00
fdfd                                          100% 1037   139.2KB/s   00:00
fdfd.json                                     100%  277    54.8KB/s   00:00
fdf-ipsets                                    100%  371    69.6KB/s   00:00
```

### Step 4b: Install `libsavl`

On the OpenWrt device, copy the shared object file to the library directory, and
create a symbolic link that reflects its soname.

> **NOTE:** If necessary, use the `objdump` utility **on the build system** to
> determine the library's soname.
>
> ```
> $ objdump -p libsavl/libsavl.so.* | grep SONAME
>   SONAME               libsavl.so.0.7
> ```

```
# ls libsavl.so.*
libsavl.so.0.7.1

# cp libsavl.so.0.7.1 /usr/lib/

# ln -s libsavl.so.0.7.1 /usr/lib/libsavl.so.0.7
```

### Step 4c: Install Other Dependencies

Use `opkg` to ensure that the JSON-C (`libjson-c5`) and `libmnl` (`libmnl0`)
libraries and the `ipset` tool are all installed.

> **NOTE:** The `libmnl0` and `ipset` packages are not required if the
> [IP set filter](ipset-filter.md) will not be used.

```
# for PKG in libjson-c5 libmnl0 ipset ; do opkg status $PKG ; done | grep ^Status
Status: install user installed
Status: install ok installed
Status: install user installed
```

### Step 4d: Install FDF

On the OpenWrt device, copy the FDF daemon executable to `/usr/bin`, create a
directory for FDF filter shared objects, and copy the filters to that directory.

```
# cp fdfd /usr/bin/

# mkdir /usr/lib/fdf-filters

# cp mdns.so ipset.so /usr/lib/fdf-filters/
```

### Step 4e: Install the Initilization Scripts

> **NOTES:**
>
> * The `fdf-ipsets` initialization script is not required if the IP set filter
>   will not be used.
>
> * Running as a non-`root` user, with only the required capabilities, is
>   currently disabled in the `fdfd` initialization script.  See
>   [this OpenWrt forum topic](https://forum.openwrt.org/t/procd-capabilities-support-in-21-02-2/123934).

```
# cp fdfd fdf-ipsets /etc/init.d/

# cp fdfd.json /etc/capabilities/
```

### Step 4f: Configuration Files

Follow the directions [here](../README.md#configuration) to create the FDF
configuration (`/etc/fdf-config.json`).

Additionally, create the `/etc/config/fdf`
[UCI](https://openwrt.org/docs/guide-user/base-system/uci) configuration, which
controls the behavior of the initialization scripts (`/etc/init.d/fdfd` and
`/etc/init.d/fdf-ipsets`).  This repository contains a sample UCI configuration
file (`openwrt/fdf`) that can be used as a reference.

As an alternative to editing the file, the `uci` command can be used to display
and modify the configuration.  Consider the sample configuration.

```
# cat /etc/config/fdf
config startup daemon
        # All network interfaces used by FDF
        option interfaces 'eth0 eth1'
        # (Optional) fdfd command-line options
        option options '-d -p'

# (Optional) IP sets to be created by the fdf-ipsets service
config ipset SET1
config ipset SET2

# uci show fdf
fdf.daemon=startup
fdf.daemon.interfaces='eth0 eth1'
fdf.daemon.options='-d -p'
fdf.SET1=ipset
fdf.SET2=ipset
```

* `fdf.daemon.interfaces` is required.  It should be a whitespace separated
  list (enclosed in double or single quotes) of all network interfaces that FDF
  will use, as either a source or destination, when forwarding packets.  The
  `fdfd` initialization script will wait until these interfaces exist before
  starting the FDF daemon.

* `fdf.daemon.options` is optional.  It can be use to pass command-line options
  to the FDF daemon.  See [*Running `fdfd`*](../README.md#running-fdfd).

* `fdf.SET1` and `fdf.SET2` specify IP sets that will be created by the
  `fdf-ipsets` initialization script.  (Technically, each is an empty UCI
  section of type `ipset`.  A future version of the `fdf-ipsets` script may
  use options within these sections to create IP sets with specific options.)
  Any IP set used by the [IP set filter](ipset-filter.md) should have such a
  section defined.

## Step 5: Configure the Device Network and Firewall

##### References

* [Runtime Requirements](../README.md#runtime-requirements)

As mentioned [above](#introduction), I do not use OpenWrt as a router, only as
"layer 2" wireless access point.  The device does not have an IP address on any
of the subnets used by my wireless networks.  Its only IP address is on my
"management" subnet, on an isolated VLAN.  Thus, it needs only a very simple
firewall configuration.  Because I am familiar with the "legacy" `iptables`
syntax used on Red Hat, Fedora, and similar distributions before the adoption of
`firewalld`, I use a
[simple initialization script](https://github.com/ipilcher/openwrt-iptables)
that allows me to use this syntax on OpenWrt.

For this reason, I cannot provide detailed instructions for configuring the
OpenWrt firewall, only general principles.

* The device must have an IPv4 address configured on any network interface that
  FDF will use to receive packets.  (If the device is being used as a router,
  this will usually already be true.)

* The device firewall must be configured to allow incoming traffic that matches
  the FDF [listeners](../README.md#listeners).  For example, if FDF is listening
  for multicast DNS packets on `eth0`, which is connected to the
  `192.168.5.0/24` subnet, then the firewall must be configured to allow traffic
  sent to IP address `224.0.0.251`, UDP port `5353`, from that network and
  subnet to be received.

* Unlike multicast DNS (usually), most network discovery protocols use unicast
  response packets.  FDF will not forward these response packets; the network
  router (usually the OpenWrt device) must be configured to route them to their
  destination (along with any "post-discovery" traffic).

  When the OpenWrt device is also the router (the most common setup), the device
  firewall must be configured to allow the routed traffic.  This can be achieved
  with static rules or with the [FDF IP set filter](ipset-filter.md).

## Step 6: Final Steps

### Step 6a: Run FDF Manually

It is recommended to first run FDF manually, with all debugging enabled.

```
# fdfd -d -p
DEBUG: config.c:387: Parsing filter (/filters/mdns_query)
DEBUG: mdns_query: mDNS filter mode set to STATEFUL
DEBUG: mdns_query: Instance set to IPSET mode
⋮
```

After confirming that FDF is working as expected, terminate the program with
`Ctrl-C` (`SIGINT`).

### Step 6b: Run FDF as a Service

Run FDF as a service, to ensure that the initialization script works.

```
# service fdfd start

# service fdfd status
running
```

### Step 6c: Enable the Services and Reboot

Finally, enable the required services &mdash; `fdfd` and (optionally)
`fdf-ipsets` and reboot the device.

```
# service fdfd enable

# service fdf-ipsets enable

# reboot
```

When the device has finished booting, verify that any required IP sets were
created (`ipset list`) and the FDF daemon is running as expected.
