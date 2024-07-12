import pytest
from sigma.collection import SigmaCollection
from sigma.backends.duckdb import DuckDbBackend

TABLE_NAME = "table"
REVERSE_INDEXED_FIELDS = [
    "fieldA"
]

@pytest.fixture
def duckdb_backend():
    return DuckDbBackend(table_name=TABLE_NAME, reverse_indexed_fields=REVERSE_INDEXED_FIELDS)

# TODO: implement tests for some basic queries and their expected results.
def test_duckdb_and_expression(duckdb_backend : DuckDbBackend):
    assert duckdb_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """)
    ) == [f"SELECT * FROM {TABLE_NAME} WHERE fieldA ILIKE 'valueA' AND fieldB ILIKE 'valueB'"]

def test_duckdb_or_expression(duckdb_backend : DuckDbBackend):
    assert duckdb_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA
                sel2:
                    fieldB: valueB
                condition: 1 of sel*
        """)
    ) == [f"SELECT * FROM {TABLE_NAME} WHERE fieldA ILIKE 'valueA' OR fieldB ILIKE 'valueB'"]

def test_duckdb_and_or_expression(duckdb_backend : DuckDbBackend):
    assert duckdb_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA1
                        - valueA2
                    fieldB:
                        - valueB1
                        - valueB2
                condition: sel
        """)
    ) == [f"SELECT * FROM {TABLE_NAME} WHERE (fieldA ILIKE 'valueA1' OR fieldA ILIKE 'valueA2') AND (fieldB ILIKE 'valueB1' OR fieldB ILIKE 'valueB2')"]

def test_duckdb_or_and_expression(duckdb_backend : DuckDbBackend):
    assert duckdb_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA1
                    fieldB: valueB1
                sel2:
                    fieldA: valueA2
                    fieldB: valueB2
                condition: 1 of sel*
        """)
    ) == [f"SELECT * FROM {TABLE_NAME} WHERE fieldA ILIKE 'valueA1' AND fieldB ILIKE 'valueB1' OR fieldA ILIKE 'valueA2' AND fieldB ILIKE 'valueB2'"]

def test_duckdb_in_expression(duckdb_backend : DuckDbBackend):
    assert duckdb_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA
                        - valueB
                        - valueC*
                condition: sel
        """)
    ) == [f"SELECT * FROM {TABLE_NAME} WHERE fieldA ILIKE 'valueA' OR fieldA ILIKE 'valueB' OR fieldA ILIKE 'valueC%'"]

def test_duckdb_escape_wildcards_in_like_expressions(duckdb_backend : DuckDbBackend):
    assert duckdb_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: value_A
                    fieldB: value%B
                condition: sel
        """)
    ) == [f"SELECT * FROM {TABLE_NAME} WHERE fieldA ILIKE 'value\\_A' ESCAPE '\\' AND fieldB ILIKE 'value\\%B' ESCAPE '\\'"]

def test_duckdb_regex_query(duckdb_backend : DuckDbBackend):
    assert duckdb_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: foo.*bar
                    fieldB: foo
                condition: sel
        """)
    ) == [f"SELECT * FROM {TABLE_NAME} WHERE fieldA ~ '(?i)foo.*bar' AND fieldB ILIKE 'foo'"]

def test_duckdb_cidr_query(duckdb_backend : DuckDbBackend):
    assert duckdb_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field|cidr: 192.168.0.0/16
                condition: sel
        """)
    ) == [f"SELECT * FROM {TABLE_NAME} WHERE field ILIKE '192.168.%'"]

def test_duckdb_field_name_with_whitespace(duckdb_backend : DuckDbBackend):
    assert duckdb_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field name: value
                condition: sel
        """)
    ) == [f"SELECT * FROM {TABLE_NAME} WHERE \"field name\" ILIKE 'value'"]
