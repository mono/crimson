ifndef PROFILE
PROFILE=net_1_1
endif

ifeq ($(PROFILE),net_2_0)
MCS=gmcs /d:NET_2_0,NET_1_1
else
MCS=mcs /d:NET_1_1
endif

all: managed native bf

managed: managed.cs
	$(MCS) managed.cs -r:Mono.Security.dll

native: native.cs
	cp ../../../lib/$(PROFILE)/Crimson.MHash.dll .
	$(MCS) native.cs -r:Crimson.MHash.dll

bf: bf.cs
	$(MCS) bf.cs

bigfile: bf 
	mono bf.exe bigfile 250000000

md5: bigfile
	time md5sum bigfile
	time mono managed.exe MD5 bigfile
	time mono native.exe MD5 bigfile

sha1: bigfile
	time sha1sum bigfile
	time mono managed.exe SHA1 bigfile
	time mono native.exe SHA1 bigfile

benchmark: md5 sha1

clean:
	rm -f bigfile
	rm -f *.exe
	rm -f *.dll
