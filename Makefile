XLOGIN = xshche05

all: build

build: *.cs *.csproj
	dotnet publish --ucr -c Release -o .
	
clean:
	rm -rf bin obj
	
pack: *.cs *.csproj
	zip $(XLOGIN).zip -r Makefile *.cs *.csproj LICENSE README.md
	