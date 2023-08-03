![Status](https://img.shields.io/badge/Status-pre--release-orange)

# pySigma SQLite Backend

This is the SQLite backend for pySigma. It provides the package `sigma.backends.sqlite` with the `SQLiteBackend` class.

The backend supports the following backend options (passed with `-O` to `sigma convert`, or as keyword constructor arguments):

* `table_name`: The name of the SQLite table to search in
* `reverse_indexed_fields`: A list of fields that are indexed in reverse, as an optimization for `endswith` conditions

Further, it contains the following processing pipelines in `sigma.pipelines.sqlite`:

* `sqlite_pipeline`: Reject rules that aren't supported by this backend

It supports the following output formats:

* `default`: plain sqlite queries
* `json`: rule and sqlite query as json object

This backend is currently maintained by:

* [DenizenB](https://github.com/DenizenB/)

## SQLite User Functions

This backend generates queries containing the functions `REGEXP` and `REV` and expects them to be defined as user functions in SQLite.

Here's an example implementation in Python:

```python
import re

def regexp(pattern, column, search=re.search, flags=re.IGNORECASE):
    return 1 if search(pattern, column, flags) else 0

db.create_function('regexp', 2, regexp, deterministic=True)

def rev(text):
    return text[::-1] if text is not None else None

db.create_function("rev", 1, rev, deterministic=True)
```
