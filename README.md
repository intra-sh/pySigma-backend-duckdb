![Status](https://img.shields.io/badge/Status-pre--release-orange)

# pySigma DuckDB Backend

This is a DuckDB backend for pySigma. It provides the package `sigma.backends.duckdb` with the `DuckDBBackend` class.

The backend supports the following backend options (passed with `-O` to `sigma convert`, or as keyword constructor arguments):

* `table_name`: The name of the DuckDB table to search in

Further, it contains the following processing pipelines in `sigma.pipelines.duckdb`:

* `duckdb_pipeline`: Reject rules that aren't supported by this backend

It supports the following output formats:

* `default`: plain queries
* `json`: rule and query as json object

This backend is currently maintained by:

* [Patrik-NTT](https://github.com/Patrik-NTT/)
