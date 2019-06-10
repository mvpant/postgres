# src/test/modules/test_artree/Makefile

MODULE_big = test_artree
OBJS = test_artree.o $(WIN32RES)
PGFILEDESC = "artree - test code for artree"

EXTENSION = test_artree
DATA = test_artree--1.0.sql

REGRESS = test_artree

ifdef USE_PGXS
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
else
subdir = src/test/modules/test_artree
top_builddir = ../../../..
include $(top_builddir)/src/Makefile.global
include $(top_srcdir)/contrib/contrib-global.mk
endif
