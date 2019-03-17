# $FreeBSD: releng/12.0/gnu/usr.bin/gdb/gdb/Makefile 328926 2018-02-06 12:12:44Z bapt $

PROG=	gdb${GDB_SUFFIX}
SRCS=	gdb.c

BULIBS= ${OBJ_BU}/libbfd/libbfd.a ${OBJ_BU}/libopcodes/libopcodes.a \
	${OBJ_BU}/libiberty/libiberty.a
GDBLIBS= ${OBJ_GDB}/libgdb/libgdb.a

# libthread_db.so calls back into gdb for the proc services.  Make all the
# global symbols visible.
LDFLAGS+= -Wl,-E

DPADD=	${GDBLIBS} ${BULIBS}
LDADD=	${GDBLIBS} ${BULIBS}
LIBADD+=	m edit ncursesw gnuregex

.include <bsd.prog.mk>
CFLAGS+=	-DDEBUGDIR=\"${DEBUGDIR}\"
