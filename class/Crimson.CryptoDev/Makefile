CSC=gmcs

CSC_FLAGS= -optimize
#CSC_FLAGS= -debug

SOURCES = \
	Crimson.CryptoDev/CryptoDev.cs			\
	Crimson.CryptoDev/CryptoDevTransform.cs		\
	Crimson.CryptoDev/Ioctl.cs			\
	Crimson.CryptoDev/HashHelper.cs			\
	Crimson.CryptoDev/Helper.cs			\
	Crimson.Security.Cryptography/RijndaelKernel.cs	\
	CryptoTools.cs 					\
	AssemblyInfo.cs					\
	../../common/Locale.cs

all: Crimson.CryptoDev.dll

CryptoTools.cs:
	wget https://raw.github.com/mono/mono/master/mcs/class/Mono.Security/Mono.Security.Cryptography/CryptoTools.cs

GENERATED_SOURCES = \
	Crimson.Security.Cryptography/AesKernel.g.cs	\
	Crimson.Security.Cryptography/SHA1Kernel.g.cs	\
	Crimson.Security.Cryptography/SHA256Kernel.g.cs

tools/generator.exe: tools/generator.cs
	$(CSC) -t:exe -out:$@ $^

$(GENERATED_SOURCES): tools/generator.exe
	mono tools/generator.exe Crimson.Security.Cryptography

AssemblyInfo.cs:
	@ver='tarball'; \
	if test -d $(CURDIR)/../../.git; then \
	  cd $(CURDIR)/../..; \
	  LANG=C; export LANG; \
	  branch=`git branch | grep '^\*' | cut -d ' ' -f 2`; \
	  version=`git log --no-color --first-parent -n1 --pretty=format:%h`; \
	  if [ "$$branch" = '(no' ]; then \
	    ver="$$version"; \
	  else \
	    ver="$$branch/$$version"; \
	  fi; \
	  cd $(CURDIR); \
	fi; \
	( \
	  echo "using System.Reflection;"; \
	  echo "[assembly:AssemblyInformationalVersionAttribute(\"$${ver}\")]"; \
	) > $@

Crimson.CryptoDev.dll: $(SOURCES) $(GENERATED_SOURCES)
	$(CSC) $(CSC_FLAGS) $^ -t:library -unsafe -out:$@ -keyfile:../crimson.snk

torture.exe: Crimson.CryptoDev.dll tools/torture.cs
	dmcs -debug tools/torture.cs -r:Crimson.CryptoDev.dll -out:torture.exe

torture: torture.exe
	mono --debug torture.exe -v

clean:
	rm -f torture.exe
	rm -f tools/generator.exe
	rm -f $(GENERATED_SOURCES) CryptoTools.cs AssemblyInfo.cs
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
	@echo running tests without buffer limits
	nunit-console Crimson.CryptoDev.Tests.dll
	@echo running tests with Rijndael/AES limited to 1936 and SHA1 limited to 1920 bytes
	CRIMSON_AES_BUFFER_BLOCK_SIZE=1936 CRIMSON_RIJNDAEL_BUFFER_BLOCK_SIZE=1936 CRIMSON_SHA1_BUFFER_BLOCK_SIZE=1920 nunit-console Crimson.CryptoDev.Tests.dll

