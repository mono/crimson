CSC=mcs

all: hashperf.exe cryptperf.exe

hashperf.exe: hashperf.cs
	$(CSC) -debug hashperf.cs

cryptperf.exe: cryptperf.cs
	$(CSC) -debug cryptperf.cs

clean:
	rm *.exe*
