#!/usr/bin/bash

MD5SUM=`sed -e '/^#define FDF_FILTER_API_VER.*$/d' \
		-e '/^#define FDF_FILTER_CTOR.*$/d' \
		fdf-filter.h \
	| md5sum \
	| awk '{ print $1 }'`

HASH=`printf '%16x\n' $(( 0x${MD5SUM:0:16} ^ 0x${MD5SUM:16} ))`

HDR_API_VER="#define FDF_FILTER_API_VER\t((uint64_t)0x${HASH}ULL)"
HDR_CTOR="#define FDF_FILTER_CTOR\t\tctor_${HASH}"

sed -e "s/^#define FDF_FILTER_API_VER.*$/${HDR_API_VER}/" \
	-e "s/^#define FDF_FILTER_CTOR.*$/${HDR_CTOR}/" \
	-i fdf-filter.h
