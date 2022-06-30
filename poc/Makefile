SAGEFILES := $(basename $(notdir $(wildcard *.sage)))
PYFILES := $(addprefix sagelib/, $(addsuffix .py,$(SAGEFILES)))
.PRECIOUS: $(PYFILES)

.PHONY: pyfiles
pyfiles: sagelib/__init__.py $(PYFILES)

sagelib/__init__.py:
	mkdir -p sagelib
	echo pass > sagelib/__init__.py

sagelib/%.py: %.sage
	@echo "Parsing $<"
	@sage --preparse $<
	@mv $<.py $@

test: pyfiles
	sage common.sage
	sage field.sage
	sage prg.sage
	sage flp.sage
	sage flp_generic.sage
	sage idpf.sage
	sage idpf_poplar.sage
	sage daf.sage
	sage vdaf.sage
	sage vdaf_prio3.sage
	sage vdaf_poplar1.sage
