all: victim fake-dll detector static-scan

victim:
	cd victim && make

fake-dll:
	cd fake-dll && make

detector:
	cd detector && make

static-scan:
	cd static-scan && make

clean:
	cd victim && make clean
	cd fake-dll && make clean
	cd detector && make clean
	cd static-scan && make clean