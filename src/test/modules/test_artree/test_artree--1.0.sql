/* src/test/modules/test_artree/test_artree--1.0.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION test_artree" to load this file. \quit

CREATE TYPE SHMT AS (LEAFS INT, NODE4 INT, NODE16 INT, NODE48 INT, NODE256 INT);

CREATE FUNCTION test_artree(query text)
RETURNS pg_catalog.void STRICT
AS 'MODULE_PATHNAME' LANGUAGE C;

CREATE FUNCTION pg_stat_get_shmtree()
RETURNS RECORD
AS 'MODULE_PATHNAME', 'pg_stat_get_shmtree'
LANGUAGE C;

CREATE VIEW PG_STAT_SHMTREE
AS SELECT (P).LEAFS, (P).NODE4, (P).NODE16, (P).NODE48, (P).NODE256
FROM (SELECT PG_STAT_GET_SHMTREE()::TEXT::SHMT AS P) T;
