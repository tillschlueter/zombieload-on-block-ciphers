SUBDIRS := $(shell find . -mindepth 2 -iname Makefile -printf '"%h" ')

.PHONY: all
default: all

all:
	for SUBDIR in $(SUBDIRS) ; do \
		$(MAKE) -C $$SUBDIR ; \
	done
	
clean:
	for SUBDIR in $(SUBDIRS) ; do \
		$(MAKE) clean -C $$SUBDIR ; \
	done
