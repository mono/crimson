ifndef PROFILE
PROFILE=net_1_1
endif

ifeq ($(PROFILE),net_2_0)
MCS=gmcs /d:NET_2_0,NET_1_1
else
MCS=mcs /d:NET_1_1
endif

all:
	$(MCS) -debug -target:library -out:../lib/$(PROFILE)/Crimson.MHash.dll @Crimson.MHash.dll.sources

install:
	gacutil -i ../lib/$(PROFILE)/Crimson.MHash.dll

clean:
	rm *.dll
	rm *.mdb
