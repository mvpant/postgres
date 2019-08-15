/* src/test/modules/test_artree/test_artree--1.0.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION test_artree" to load this file. \quit

CREATE FUNCTION test_artree(query text)
RETURNS pg_catalog.void STRICT
AS 'MODULE_PATHNAME' LANGUAGE C;
