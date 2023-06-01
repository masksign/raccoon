clean:
	rm -rf Raccoon
	cd ref-py && $(MAKE) clean
	cd ref-c && $(MAKE) -f Makefile.kat clean
	

	
