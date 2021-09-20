identifier=insomnia-plugin-oci-auth
extensions_dir=$(HOME)/Library/Application Support/Insomnia/plugins/

build:
	mkdir -p ./build/$(identifier)/node_modules
	cp README.md LICENSE main.js package.json ./build/$(identifier)/
	cp -R node_modules/* ./build/$(identifier)/node_modules

clean:
	rm -Rf ./build/

install: clean build 
	rm -rf "$(extensions_dir)$(identifier)/"
	mkdir -p "$(extensions_dir)$(identifier)/"
	cp -r ./build/$(identifier)/* "$(extensions_dir)$(identifier)/"

archive: build
	cd ./build/; zip -r OciFnAuth.zip "$(identifier)/"