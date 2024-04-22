XLOGIN = xshche05

all: build

build: *.cs *.csproj
	dotnet publish --ucr -c Release -o .

clean:
	rm -rf bin obj

dos2unix:
	dos2unix *.cs *.csproj Makefile LICENSE README.md CHANGELOG

pack: *.cs *.csproj dos2unix
	zip $(XLOGIN).zip -r Makefile *.cs *.csproj LICENSE README.md CHANGELOG diagram.png
