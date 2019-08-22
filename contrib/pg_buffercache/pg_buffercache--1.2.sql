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

CREATE FUNCTION pg_buffertree_common()
RETURNS RECORD
AS 'MODULE_PATHNAME', 'pg_buffertree_common'
LANGUAGE C PARALLEL SAFE;

-- Create a view for convenient access.
CREATE VIEW pg_buffertree_common AS
	SELECT P.* FROM pg_buffertree_common() AS P
	(leaves_used int4, node4_used int4, node16_used int4,
	 node48_used int4, node256_used int4, subtrees_used int4,
	 leaves_total int4, node4_total int4, node16_total int4,
	 node48_total int4, node256_total int4, subtrees_total int4,
	 leaves_mem int4, node4_mem int4, node16_mem int4,
	 node48_mem int4, node256_mem int4, subtrees_mem int4);

-- Don't want these to be available to public.
REVOKE ALL ON FUNCTION pg_buffertree_common() FROM PUBLIC;
REVOKE ALL ON pg_buffertree_common FROM PUBLIC;

CREATE FUNCTION pg_buffertree_stats()
RETURNS SETOF RECORD
AS 'MODULE_PATHNAME', 'pg_buffertree_stats'
LANGUAGE C PARALLEL SAFE;

-- Create a view for convenient access.
CREATE VIEW pg_buffertree AS
	SELECT P.* FROM pg_buffertree_stats() AS P
	(relfilenode oid, reltablespace oid, reldatabase oid,
	 relforknumber int2, nleaves int4, nelem4 int4, nelem16 int4,
	 nelem48 int4, nelem256 int4);

-- Don't want these to be available to public.
REVOKE ALL ON FUNCTION pg_buffertree_stats() FROM PUBLIC;
REVOKE ALL ON pg_buffertree FROM PUBLIC;
