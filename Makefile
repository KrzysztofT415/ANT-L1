.SILENT: clean
all: main clean

# BUILD MAIN && RUN AUTOMATICALLY
main:
	sage rsa.sage

# BUILD TEST && RUN AUTOMATICALLY
test:
	sage test.sage

clean:
	rm -f rsa.sage.py
	rm -f test.sage.py