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
    ) == [f"SELECT * FROM {TABLE_NAME} WHERE fieldA LIKE 'valueA' AND fieldB LIKE 'valueB'"]

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
    ) == [f"SELECT * FROM {TABLE_NAME} WHERE fieldA LIKE 'valueA' OR fieldB LIKE 'valueB'"]

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
    ) == [f"SELECT * FROM {TABLE_NAME} WHERE (fieldA LIKE 'valueA1' OR fieldA LIKE 'valueA2') AND (fieldB LIKE 'valueB1' OR fieldB LIKE 'valueB2')"]

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
    ) == [f"SELECT * FROM {TABLE_NAME} WHERE fieldA LIKE 'valueA1' AND fieldB LIKE 'valueB1' OR fieldA LIKE 'valueA2' AND fieldB LIKE 'valueB2'"]

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
    ) == [f"SELECT * FROM {TABLE_NAME} WHERE fieldA LIKE 'valueA' OR fieldA LIKE 'valueB' OR fieldA LIKE 'valueC%'"]

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
    ) == [f"SELECT * FROM {TABLE_NAME} WHERE fieldA REGEXP 'foo.*bar' AND fieldB LIKE 'foo'"]

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
    ) == [f"SELECT * FROM {TABLE_NAME} WHERE field LIKE '192.168.%'"]

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
    ) == [f"SELECT * FROM {TABLE_NAME} WHERE `field name` LIKE 'value'"]

# TODO: implement tests for all backend features that don't belong to the base class defaults, e.g. features that were
# implemented with custom code, deferred expressions etc.

def test_duckdb_reversed_endswith_optimization(duckdb_backend: DuckDbBackend):
    assert duckdb_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: '*valueA'
                    fieldB: '*valueB'
                condition: sel
        """)
    ) == [f"SELECT * FROM {TABLE_NAME} WHERE REV(fieldA) LIKE 'Aeulav%' AND fieldB LIKE '%valueB'"]


def test_duckdb_format1_output(duckdb_backend : DuckDbBackend):
    """Test for output format format1."""
    # TODO: implement a test for the output format
    pass

def test_duckdb_format2_output(duckdb_backend : DuckDbBackend):
    """Test for output format format2."""
    # TODO: implement a test for the output format
    pass
