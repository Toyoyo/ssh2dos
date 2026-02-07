#
# OpenWatcom makefile for SSH2DOS (protected mode version)
#

# Debug
DEBUG=-od

# uncomment this for B&W mode
COLOR = -DCOLOR

#################################################################
# In normal cases, no other settings should be changed below!!! #
#################################################################

CC = wcc386
LINKER = wlink LibPath lib:$(%WATT_ROOT)/lib

CFLAGS = -zq -mf -3r -bt=dos -s $(DEBUG) -i=$(%WATCOM)/h:./include:$(%WATT_ROOT)/inc $(COLOR) -za99
# -DMEMWATCH

.c.o:	
        $(CC) $(CFLAGS) $[@

LIBS = lib/misc.lib lib/crypto.lib lib/ssh.lib lib/vt100.lib $(%WATT_ROOT)/lib/wattcpwf.lib lib/zlib_f.lib

all:    ssh2d386.exe sftpd386.exe scp2d386.exe tel386.exe

ssh2d386.exe : ssh2dos.o $(LIBS)
	$(LINKER) @ssh2d386.lnk

sftpd386.exe : sftpdos.o sftp.o $(LIBS)
	$(LINKER) @sftpd386.lnk

scp2d386.exe : scpdos.o $(LIBS)
	$(LINKER) @scp2d386.lnk

tel386.exe   : telnet.o lib/misc.lib lib/vt100.lib $(%WATT_ROOT)/lib/wattcpwf.lib
	$(LINKER) @tel386.lnk

lib/crypto.lib: sshrsa.o sshdes.o sshmd5.o sshbn.o sshpubk.o int64.o sshaes.o  sshsha.o sshsh512.o sshdss.o sshsh256.o ed25519.o
	wlib -b -c lib/crypto.lib -+sshrsa.o -+sshdes.o -+sshmd5.o -+sshbn.o -+sshpubk.o
	wlib -b -c lib/crypto.lib -+int64.o -+sshaes.o -+sshsha.o -+sshsh512.o -+sshdss.o -+sshsh256.o
	wlib -b -c lib/crypto.lib -+ed25519.o

lib/ssh.lib: negotiat.o transprt.o auth.o channel.o
	wlib -b -c lib/ssh.lib -+negotiat.o -+transprt.o -+auth.o -+channel.o

lib/vt100.lib: vttio.o vidio.o keyio.o keymap.o
	wlib -b -c lib/vt100.lib -+vttio.o -+vidio.o -+keyio.o -+keymap.o

lib/misc.lib: common.o shell.o proxy.o
	wlib -b -c lib/misc.lib  -+common.o -+shell.o -+proxy.o

clean: .SYMBOLIC
	rm -f *.o
	rm -f *.map
	rm -f lib/vt100.lib
	rm -f lib/crypto.lib
	rm -f lib/misc.lib
	rm -f lib/ssh.lib
	rm -f ssh2d386.exe
	rm -f sftpd386.exe
	rm -f scp2d386.exe
	rm -f tel386.exe
