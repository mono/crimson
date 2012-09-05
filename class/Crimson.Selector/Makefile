CSC=gmcs

SOURCES = \
	Crimson.Selector/AlgorithmSelector.cs			\
	Crimson.Security.Cryptography/AesSelector.cs		\
	Crimson.Security.Cryptography/RijndaelSelector.cs	\
	Crimson.Security.Cryptography/SHA1Selector.cs		\
	Crimson.Security.Cryptography/SHA256Selector.cs

all: Crimson.Selector.dll

Crimson.Selector.dll: $(SOURCES)
	$(CSC) -debug $(SOURCES) -t:library -out:$@ -keyfile:../crimson.snk

clean:
	rm -f *.dll*

BASE_TESTS = \
	../../tests/AesTest.cs			\
	../../tests/HashAlgorithmTest.cs	\
	../../tests/RijndaelTest.cs		\
	../../tests/SHA1Test.cs			\
	../../tests/SHA256Test.cs		\
	../../tests/SymmetricAlgorithmTest.cs

TESTS = \
	Tests/AesSelectorTest.cs	\
	Tests/RijndaelSelectorTest.cs	\
	Tests/SHA1SelectorTest.cs	\
	Tests/SHA256SelectorTest.cs	\

Crimson.Selector.Tests.dll: $(BASE_TESTS) $(TESTS) Crimson.Selector.dll
	$(CSC) -debug $(BASE_TESTS) $(TESTS) -t:library -out:$@ -r:Crimson.Selector.dll -pkg:mono-nunit

test: Crimson.Selector.Tests.dll

run-test: test
	rm -f Crimson.CryptoDev.dll
	@echo running tests Crimson.CryptoDev.dll available
	nunit-console Crimson.Selector.Tests.dll
	cp ../Crimson.CryptoDev/Crimson.CryptoDev.dll .
	@echo running tests without buffer limits
	nunit-console Crimson.Selector.Tests.dll
	@echo running tests with Rijndael/AES limited to 1936 and SHA1 limited to 1920 bytes
	CRIMSON_AES_BUFFER_BLOCK_SIZE=1936 CRIMSON_RIJNDAEL_BUFFER_BLOCK_SIZE=1936 CRIMSON_SHA1_BUFFER_BLOCK_SIZE=1920 nunit-console Crimson.Selector.Tests.dll
	rm -f Crimson.CryptoDev.dll

