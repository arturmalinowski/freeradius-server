TARGET	:= radiusd
SOURCES := acct.c auth.c client.c crypt.c files.c \
		  listen.c  mainconfig.c modules.c modcall.c \
		  radiusd.c stats.c soh.c connection.c \
		  session.c threads.c version.c  \
		  process.c realms.c detail.c
ifneq ($(OPENSSL_LIBS),)
SOURCES	+= cb.c tls.c tls_listen.c
endif

SRC_CFLAGS	:= -DHOSTINFO=\"${HOSTINFO}\"
TGT_INSTALLDIR  := ${sbindir}

TGT_LDLIBS	:= $(LIBS) $(LCRYPT)

# Page options requeired for linking against LuaJIT and possiby others
# on OSX x86_64
ifneq (,$(findstring darwin,$(value TARGET_SYSTEM)))
TGT_LDLIBS	:= -pagezero_size 10000 -image_base 100000000 $(TGT_LDLIBS)
endif

TGT_PREREQS	:= libfreeradius-server.a libfreeradius-radius.a

# Libraries can't depend on libraries (oops), so make the binary
# depend on the EAP code...
ifneq "$(filter rlm_eap_%,${ALL_TGTS})" ""
TGT_PREREQS	+= libfreeradius-eap.a
endif
