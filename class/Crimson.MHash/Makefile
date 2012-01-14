ifndef PROFILE
PROFILE=net_2_0
endif

ifeq ($(PROFILE),net_2_0)
MCS=gmcs /d:NET_2_0,NET_1_1
else
MCS=mcs /d:NET_1_1
endif

all: Crimson.MHash.dll

Crimson.MHash.dll:
	$(MCS) -debug -target:library -out:Crimson.MHash.dll @Crimson.MHash.dll.sources -keyfile:../crimson.snk

install:
	gacutil -i Crimson.MHash.dll

BASE_TESTS = \
	../../tests/HashAlgorithmTest.cs \
	../../tests/SHA1Test.cs	\
	../../tests/SHA256Test.cs

TESTS = \
	Tests/SHA1NativeTest.cs	\
	Tests/SHA256NativeTest.cs

Crimson.MHash.Tests.dll: $(BASE_TESTS) $(GENERATED_TESTS) Crimson.MHash.dll
	mcs -debug $(BASE_TESTS) $(TESTS) -t:library -out:$@ -r:Crimson.MHash.dll -pkg:mono-nunit

test: Crimson.MHash.dll Crimson.MHash.Tests.dll

run-test: test
	nunit-console Crimson.MHash.Tests.dll

clean:
	rm *.dll
	rm *.mdb
