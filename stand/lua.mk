# $FreeBSD: releng/12.0/stand/lua.mk 329859 2018-02-23 04:04:25Z imp $

# Common flags to build lua related files

CFLAGS+=	-I${LUASRC} -I${LDRSRC} -I${LIBLUASRC}
CFLAGS+=	-DLUA_FLOAT_TYPE=LUA_FLOAT_INT64
