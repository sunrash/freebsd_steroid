# $FreeBSD: releng/12.0/share/mk/local.autodep.mk 337186 2018-08-02 21:33:45Z sjg $

.if ${.MAKE.DEPENDFILE:M*.${MACHINE}} == ""
# by default only MACHINE0 does updates
UPDATE_DEPENDFILE_MACHINE?= ${MACHINE0:U${MACHINE}}
.if ${MACHINE} != ${UPDATE_DEPENDFILE_MACHINE}
UPDATE_DEPENDFILE= no
.endif
.endif

CFLAGS+= ${CFLAGS_LAST}
CXXFLAGS+= ${CXXFLAGS_LAST}
LDFLAGS+= ${LDFLAGS_LAST}

CLEANFILES+= .depend

# handy for debugging
.SUFFIXES:  .S .c .cc .cpp .cpp-out


.S.cpp-out .c.cpp-out: .NOMETA
	@${CC} -E ${CFLAGS} ${.IMPSRC} | grep -v '^[[:space:]]*$$'

.cc.cpp-out: .NOMETA
	@${CXX} -E ${CXXFLAGS} ${.IMPSRC} | grep -v '^[[:space:]]*$$'
