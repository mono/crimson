CSC=gmcs

CSC_FLAGS= -optimize
#CSC_FLAGS= -debug

SOURCES = \
	Crimson.OpenSsl/Native.cs			\
	Crimson.OpenSsl/HashHelper.cs		\
	Crimson.OpenSsl/OpenSslCryptoTransform.cs			\
	AssemblyInfo.cs					\
	../../common/Locale.cs \
	../../common/CryptoTransformBase.cs

all: Crimson.OpenSsl.dll

GENERATED_SOURCES = \
	Crimson.Security.Cryptography/AesOpenSsl.g.cs	\
	Crimson.Security.Cryptography/RijndaelOpenSsl.g.cs	\
	Crimson.Security.Cryptography/MD5OpenSsl.g.cs	\
	Crimson.Security.Cryptography/SHA1OpenSsl.g.cs	\
	Crimson.Security.Cryptography/SHA256OpenSsl.g.cs

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

Crimson.OpenSsl.dll: $(SOURCES) $(GENERATED_SOURCES)
	$(CSC) $(CSC_FLAGS) $^ -t:library -unsafe -out:$@ -keyfile:../crimson.snk

torture.exe: Crimson.OpenSsl.dll tools/torture.cs
	dmcs -debug tools/torture.cs -r:Crimson.OpenSsl.dll -out:torture.exe

torture: torture.exe
	mono --debug torture.exe -v

clean:
	rm -f torture.exe
	rm -f tools/generator.exe
	rm -f $(GENERATED_SOURCES) AssemblyInfo.cs
	rm -f *.dll*

BASE_TESTS = \
	../../tests/AesTest.cs			\
	../../tests/HashAlgorithmTest.cs	\
	../../tests/RijndaelTest.cs		\
	../../tests/SHA1Test.cs			\
	../../tests/SHA256Test.cs		\
	../../tests/SymmetricAlgorithmTest.cs

GENERATED_TESTS = \
	Tests/AesOpenSslTests.cs		\
	Tests/RijndaelOpenSslTests.cs	\
	Tests/SHA1OpenSslTests.cs		\
	Tests/SHA256OpenSslTests.cs	\

Crimson.OpenSsl.Tests.dll: $(BASE_TESTS) $(GENERATED_TESTS) Crimson.OpenSsl.dll
	mcs -debug $(BASE_TESTS) $(GENERATED_TESTS) -t:library -out:$@ -r:Crimson.OpenSsl.dll -pkg:mono-nunit

test: Crimson.OpenSsl.Tests.dll

run-test: test
	@echo running tests
	nunit-console Crimson.OpenSsl.Tests.dll
