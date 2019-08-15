/* contrib/pg_buffercache/pg_buffercache--1.2.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pg_buffercache" to load this file. \quit

-- Register the function.
CREATE FUNCTION pg_buffercache_pages()
RETURNS SETOF RECORD
AS 'MODULE_PATHNAME', 'pg_buffercache_pages'
LANGUAGE C PARALLEL SAFE;

-- Create a view for convenient access.
CREATE VIEW pg_buffercache AS
	SELECT P.* FROM pg_buffercache_pages() AS P
	(bufferid integer, relfilenode oid, reltablespace oid, reldatabase oid,
	 relforknumber int2, relblocknumber int8, isdirty bool, usagecount int2,
	 pinning_backends int4);

-- Don't want these to be available to public.
REVOKE ALL ON FUNCTION pg_buffercache_pages() FROM PUBLIC;
REVOKE ALL ON pg_buffercache FROM PUBLIC;

CREATE FUNCTION pg_stat_buftree()
RETURNS RECORD
AS 'MODULE_PATHNAME', 'pg_stat_buftree'
LANGUAGE C;

CREATE TYPE ART_STAT_TYPE AS (
    LEAFS INT, NODE4 INT, NODE16 INT, NODE48 INT, NODE256 INT, SUBTREES INT,
    NLEAFS INT, NNODE4 INT, NNODE16 INT, NNODE48 INT, NNODE256 INT, NSUBTREES INT,
	LEAFS_MEM INT, NODE4_MEM INT, NODE16_MEM INT,
	NODE48_MEM INT, NODE256_MEM INT, SUBTREES_MEM INT);

CREATE VIEW PG_STAT_BUFTREE
AS SELECT (P).LEAFS, (P).NODE4, (P).NODE16, (P).NODE48, (P).NODE256, (P).SUBTREES
FROM (SELECT PG_STAT_BUFTREE()::TEXT::ART_STAT_TYPE AS P) T
UNION ALL
SELECT (P).NLEAFS, (P).NNODE4, (P).NNODE16, (P).NNODE48, (P).NNODE256, (P).NSUBTREES
FROM (SELECT PG_STAT_BUFTREE()::TEXT::ART_STAT_TYPE AS P) T
UNION ALL
SELECT (P).LEAFS_MEM, (P).NODE4_MEM, (P).NODE16_MEM,
	(P).NODE48_MEM, (P).NODE256_MEM, (P).SUBTREES_MEM
FROM (SELECT PG_STAT_BUFTREE()::TEXT::ART_STAT_TYPE AS P) T
UNION ALL
SELECT (P).LEAFS_MEM/1048576, (P).NODE4_MEM/1048576, (P).NODE16_MEM/1048576,
	(P).NODE48_MEM/1048576, (P).NODE256_MEM/1048576, (P).SUBTREES_MEM/1048576
FROM (SELECT PG_STAT_BUFTREE()::TEXT::ART_STAT_TYPE AS P) T;
