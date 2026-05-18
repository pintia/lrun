.PHONY: default install clean deb

default:
	cd src && rake
	make -C tools/mirrorfs
	make -C tools/netns-empty
	make -C tools/netns-empty-lo

install:
	cd src && rake install
	make install -C tools/mirrorfs
	make install -C tools/netns-empty
	make install -C tools/netns-empty-lo

clean:
	cd src && rake clean
	make clean -C tools/mirrorfs
	make clean -C tools/netns-empty
	make clean -C tools/netns-empty-lo

deb:
	debuild -i -us -uc -b
