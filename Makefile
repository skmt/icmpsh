#
# icmpsh's Makefile
#

#======================================================
# chose your os type
#======================================================
OS=-DMACOSX
#OS=-DFREEBSD 
#OS=-DSOLARIS
#OS=-DLINUX



#--------------------------------------------------------------------------
# compile option
#--------------------------------------------------------------------------
CC	= gcc
TAGS	= ctags	# for vi
OPTIM	= -O -pipe
CFLAGS	= $(OS) -pedantic -g -Wall $(OPTIM)
LDFLAGS	= # nothing

#--------------------------------------------------------------------------
# include and library
#--------------------------------------------------------------------------
INCDIRS	= -I./

#--------------------------------------------------------------------------
# target and dependency
#--------------------------------------------------------------------------
COMMON_SRC = openpty.c utils.c
CLIENT_SRC = icmpsh.c $(COMMON_SRC)
SERVER_SRC = icmpshd.c $(COMMON_SRC)
COMMON_OBJ = openpty.o utils.o
CLIENT_OBJ = $(COMMON_OBJ) icmpsh.o
SERVER_OBJ = $(COMMON_OBJ) icmpshd.o

CLIENT_TARGET = icmpsh
SERVER_TARGET = icmpshd
TARGET	= $(CLIENT_TARGET) $(SERVER_TARGET)


#--------------------------------------------------------------------------
# linked library handling
#--------------------------------------------------------------------------
ifneq ($(findstring -DSOLARIS,$(OS)),)
 SYSLIBS= -lsocket -lnsl
endif
ifneq ($(findstring -DFREEBSD,$(OS)),)
# SYSLIBS= -lutil
 SYSLIBS=
endif
ifneq ($(findstring -DMACOSX,$(OS)),)
 SYSLIBS=
endif


#--------------------------------------------------------------------------
# rule
#--------------------------------------------------------------------------

all: $(TARGET)

$(CLIENT_TARGET): $(CLIENT_OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(INCDIRS) $(SYSLIBS)

$(SERVER_TARGET): $(SERVER_OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(INCDIRS) $(SYSLIBS)

clean:
	rm -f $(TARGET) *.exe *.o core.* tags .gdb*

ctags:
	ctags *.c *.h

etags:
	etags *.c *.h

.c.o:
	$(CC) -c -o $@ $(CFLAGS) $(INCDIRS) $^

# end of makefile
