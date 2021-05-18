/*
 *  proto.h
 *
 *  copyright (c) 2020 HANATAKA Shinya
 *  copyright (c) 2020 Internet Initiative Japan Inc.
 */
#pragma once
#ifndef _PROTO_H
#define _PROTO_H

enum {
	PROTO_NONE    = 0,
	PROTO_IP4     = 1,
	PROTO_IP6     = 2,
	PROTO_ALL     = 3,
};

enum {
	VNI_ACL       = 0xfffffffbU,
	VNI_ALL       = 0xfffffffcU,
	VNI_ANY       = 0xfffffffdU,
	VNI_WORK      = 0xfffffffeU,
	VNI_INVALID   = 0xffffffffU,
};

#endif /* _PROTO_H */
