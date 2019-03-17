# $FreeBSD: releng/12.0/lib/libclang_rt/ubsan_standalone_cxx/Makefile 327952 2018-01-14 00:08:34Z dim $

.include <bsd.init.mk>

LIB=		clang_rt.ubsan_standalone_cxx-${CRTARCH}

CXXFLAGS+=	-frtti

SRCS+=		ubsan/ubsan_handlers_cxx.cc
SRCS+=		ubsan/ubsan_type_hash.cc
SRCS+=		ubsan/ubsan_type_hash_itanium.cc

.include <bsd.lib.mk>
