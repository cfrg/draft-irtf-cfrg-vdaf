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
	sage -python common.py
	sage field.sage
	sage prg.sage
	sage -python flp.py
	sage flp_generic.sage
	sage -python idpf.py
	sage idpf_poplar.sage
	sage -python daf.py
	sage -python vdaf.py
	sage vdaf_prio3.sage
	sage vdaf_poplar1.sage
