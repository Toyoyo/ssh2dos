# Makefile for zlib
# OpenWatcom large model
# Last updated: 28-Dec-2005

# To use, do "wmake -f watcom_l.mak"

C_SOURCE =  adler32.c  compress.c crc32.c   deflate.c    &
	    gzclose.c  gzlib.c    gzread.c  gzwrite.c    &
            infback.c  inffast.c  inflate.c inftrees.c   &
            trees.c    uncompr.c  zutil.c

OBJS =      adler32.o  compress.o crc32.o   deflate.o    &
	    gzclose.o  gzlib.o    gzread.o  gzwrite.o    &
            infback.o  inffast.o  inflate.o inftrees.o   &
            trees.o    uncompr.o  zutil.o

CC       = wcc
LINKER   = wcl
CFLAGS   = -zq -ml -s -bt=dos -oilrtfm -fr=nul -wx
ZLIB_LIB = zlib_l.lib

.c.o:
        $(CC) $(CFLAGS) $[@

all: $(ZLIB_LIB)

$(ZLIB_LIB): $(OBJS)
	wlib -b -c $(ZLIB_LIB) -+adler32.o  -+compress.o -+crc32.o
	wlib -b -c $(ZLIB_LIB) -+gzclose.o  -+gzlib.o    -+gzread.o   -+gzwrite.o
        wlib -b -c $(ZLIB_LIB) -+deflate.o  -+infback.o
        wlib -b -c $(ZLIB_LIB) -+inffast.o  -+inflate.o  -+inftrees.o
        wlib -b -c $(ZLIB_LIB) -+trees.o    -+uncompr.o  -+zutil.o

example.exe: $(ZLIB_LIB) test/example.o
	$(LINKER) -fe=example.exe example.o $(ZLIB_LIB)

minigzip.exe: $(ZLIB_LIB) minigzip.o
	$(LINKER) -fe=minigzip.exe minigzip.o $(ZLIB_LIB)

clean: .SYMBOLIC
          rm -f *.o
          rm -f $(ZLIB_LIB)
          @echo Cleaning done
