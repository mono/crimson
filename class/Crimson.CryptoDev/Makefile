CSC=gmcs

SOURCES = \
	Crimson.CryptoDev/CryptoDev.cs			\
	Crimson.CryptoDev/CryptoDevTransform.cs		\
	Crimson.CryptoDev/Ioctl.cs			\
	Crimson.CryptoDev/HashHelper.cs			\
	Crimson.CryptoDev/Helper.cs			\
	Crimson.Security.Cryptography/RijndaelKernel.cs	\
	CryptoTools.cs 					\
	../../common/Locale.cs

all: Crimson.CryptoDev.dll

CryptoTools.cs:
	wget https://raw.github.com/mono/mono/master/mcs/class/corlib/Mono.Security.Cryptography/CryptoTools.cs

GENERATED_SOURCES = \
	Crimson.Security.Cryptography/AesKernel.g.cs	\
	Crimson.Security.Cryptography/SHA1Kernel.g.cs	\
	Crimson.Security.Cryptography/SHA256Kernel.g.cs

tools/generator.exe: tools/generator.cs
	$(CSC) -t:exe -out:$@ $^

$(GENERATED_SOURCES): tools/generator.exe
	mono tools/generator.exe Crimson.Security.Cryptography

Crimson.CryptoDev.dll: $(SOURCES) $(GENERATED_SOURCES)
	$(CSC) -debug $(SOURCES) $(GENERATED_SOURCES) -t:library -unsafe -out:$@ -keyfile:../crimson.snk

torture.exe: Crimson.CryptoDev.dll tools/torture.cs
	dmcs -debug tools/torture.cs -r:Crimson.CryptoDev.dll -out:torture.exe

torture: torture.exe
	mono --debug torture.exe -v

clean:
	rm -f torture.exe
	rm -f tools/generator.exe
	rm -f $(GENERATED_SOURCES) CryptoTools.cs
	rm -f *.dll*

BASE_TESTS = \
	../../tests/AesTest.cs			\
	../../tests/HashAlgorithmTest.cs	\
	../../tests/RijndaelTest.cs		\
	../../tests/SHA1Test.cs			\
	../../tests/SHA256Test.cs		\
	../../tests/SymmetricAlgorithmTest.cs

GENERATED_TESTS = \
	Tests/AesKernelTest.cs		\
	Tests/CryptoDevTest.cs		\
	Tests/RijndaelKernelTest.cs	\
	Tests/SHA1KernelTest.cs		\
	Tests/SHA256KernelTest.cs	\

Crimson.CryptoDev.Tests.dll: $(BASE_TESTS) $(GENERATED_TESTS) Crimson.CryptoDev.dll
	mcs -debug $(BASE_TESTS) $(GENERATED_TESTS) -t:library -out:$@ -r:Crimson.CryptoDev.dll -pkg:mono-nunit

test: Crimson.CryptoDev.Tests.dll

run-test: test
	nunit-console Crimson.CryptoDev.Tests.dll

