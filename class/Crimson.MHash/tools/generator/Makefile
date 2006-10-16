all: generator.cs
	mcs -debug generator.cs ../../Crimson.MHash/MHashId.cs ../../Crimson.MHash/MHashWrapper.cs

update: all
	mono --debug generator.exe ../../Crimson.Security.Cryptography

clean:
	rm *.exe
	rm *.mdb
