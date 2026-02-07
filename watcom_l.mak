#
# OpenWatcom makefile for SSH2DOS (real mode - large)
#

# Debug
#DEBUG=-d2

# uncomment this for B&W mode
COLOR = -DCOLOR

#################################################################
# In normal cases, no other settings should be changed below!!! #
#################################################################

CC = wcc
LINKER = wlink LibPath lib:$(%WATT_ROOT)/lib

CFLAGS = -zq -ml -0 -bt=dos -zt -s
CFLAGS += $(DEBUG) -i=$(%WATCOM)/h:include:$(%WATT_ROOT)/inc $(COLOR)
# -DMEMWATCH

.c.o:	
        $(CC) $(CFLAGS) $[@

LIBS = lib/misc.lib lib/crypto.lib lib/ssh.lib lib/vt100.lib $(%WATT_ROOT)/lib/wattcpwl.lib lib/zlib_l.lib

all:    ssh2dos.exe sftpdos.exe scp2dos.exe telnet.exe

ssh2dos.exe : ssh2dos.o $(LIBS)
	$(LINKER) @ssh2dos.lnk

sftpdos.exe : sftpdos.o sftp.o $(LIBS)
	$(LINKER) @sftpdos.lnk

scp2dos.exe : scpdos.o $(LIBS)
	$(LINKER) @scp2dos.lnk

telnet.exe  : telnet.o lib/misc.lib lib/vt100.lib $(%WATT_ROOT)/lib/wattcpwl.lib
	$(LINKER) @telnet.lnk

ttytest.exe : ttytest.o $(LIBS)
	$(LINKER) @ttytest.lnk

lib/crypto.lib: sshrsa.o sshdes.o sshmd5.o sshbn.o sshpubk.o int64.o sshaes.o  sshsha.o sshsh512.o sshdss.o sshsh256.o ed25519.o
	wlib -b -c lib/crypto.lib -+sshrsa.o -+sshdes.o -+sshmd5.o -+sshbn.o -+sshpubk.o
	wlib -b -c lib/crypto.lib -+int64.o -+sshaes.o -+sshsha.o -+sshsh512.o -+sshdss.o -+sshsh256.o
	wlib -b -c lib/crypto.lib -+ed25519.o

lib/ssh.lib: negotiat.o transprt.o auth.o channel.o
	wlib -b -c lib/ssh.lib -+negotiat.o -+transprt.o -+auth.o -+channel.o

lib/vt100.lib: vttio.o vidio.o keyio.o keymap.o
	wlib -b -c lib/vt100.lib -+vttio.o -+vidio.o -+keyio.o -+keymap.o

lib/misc.lib: common.o shell.o proxy.o
	wlib -b -c lib/misc.lib -+common.o -+shell.o -+proxy.o

clean: .SYMBOLIC
	rm -f *.o
	rm -f *.map
	rm -f lib/vt100.lib
	rm -f lib/crypto.lib
	rm -f lib/misc.lib
	rm -f lib/ssh.lib
	rm -f ssh2dos.exe
	rm -f scp2dos.exe
	rm -f sftpdos.exe
	rm -f telnet.exe
	rm -f ttytest.exe
