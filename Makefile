# vim: tabstop=8 noexpandtab

PEP8=pep8
#PEP8ARG=--ignore=E127,E265,E101,E128,E201,E202,E203,E211,E302,E303,W191,E501
# E203 space before ":"
# E201 whitespace after '('
# E202 whitespace before ')'
PEP8ARG=--ignore=E203,E201,E202
REPO=git@bitbucket.org:evilpete/scapy-watch.git
PROGS=
PLIB=
GIT=git

PEP8=pep8
PYLINT=pylint

FILES=whoshere/whoshere.py whoshere/whoshere_main.py whoshere/__init__.py \
        whoshere/utils.py whoshere/mtargets.py whoshere/webhandler.py
EXTRAS=whoshere-isy/whoshere-isy.py whoshere-iftt/whoshere-iftt.py
# whoshere-grunt/whoshere-grunt.py
BINFILES=
PYTHON=/usr/local/bin/python

all: syntax lint

syntax:
	for targ in ${FILES} ; do \
            echo $$targ ; \
	    ${PYTHON} -m py_compile $$targ ; \
	done
	for targ in ${EXTRAS} ; do \
            echo $$targ ; \
	    ${PYTHON} -m py_compile $$targ ; \
	done

style: pep8 lint

clean:
	rm -f *.pyc whoshere/*.pyc
	rm -rf dist Build whoshere.egg-info whoshere-0.1.*

lint:
	${PYLINT} whoshere

pep8:
	${PEP8} ${PEP8ARG} ${FILES}

install:
	python setup.py install --record files.txt

