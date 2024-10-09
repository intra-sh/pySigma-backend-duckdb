import re
from typing import ClassVar, Dict, Tuple, Pattern, List, Any, Optional, Union

import sigma
from sigma.conditions import ConditionItem, ConditionAND, ConditionOR, ConditionNOT, ConditionFieldEqualsValueExpression, ConditionValueExpression
from sigma.conversion.base import TextQueryBackend
from sigma.conversion.deferred import DeferredQueryExpression
from sigma.conversion.state import ConversionState
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule
from sigma.types import SigmaCompareExpression, SigmaRegularExpression, SigmaRegularExpressionFlag, SpecialChars, SigmaString

from ...pipelines.duckdb import duckdb_pipeline

# Documentation: https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html

class DuckDbBackend(TextQueryBackend):
    """DuckDB backend."""

    def __init__(
        self,
        processing_pipeline: Optional[ProcessingPipeline] = None,
        collect_errors: bool = False,
        table_name : str = "events",
    ):
        super().__init__(processing_pipeline, collect_errors)

        # Backend config
        self.table_name = self.escape_and_quote_field(table_name)


    # Operator precedence: tuple of Condition{AND,OR,NOT} in order of precedence.
    # The backend generates grouping if required
    name : ClassVar[str] = "DuckDB Backend"
    identifier : ClassVar[str] = "duckdb"
    formats : Dict[str, str] = {
        "default": "Plain queries",
        "json": "Rule and query as json lines",
    }
    requires_pipeline : bool = False
    backend_processing_pipeline : ClassVar[ProcessingPipeline] = duckdb_pipeline()

    precedence : ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (ConditionNOT, ConditionAND, ConditionOR)
    group_expression : ClassVar[str] = "({expr})"   # Expression for precedence override grouping as format string with {expr} placeholder

    # Generated query tokens
    token_separator : str = " "     # separator inserted between all boolean operators
    or_token : ClassVar[str] = "OR"
    and_token : ClassVar[str] = "AND"
    not_token : ClassVar[str] = "NOT"
    eq_token : ClassVar[str] = "="  # Token inserted between field and value (without separator)

    # String output
    ## Fields
    ### Quoting
    field_quote : ClassVar[str] = '"'                               # Character used to quote field characters if field_quote_pattern matches (or not, depending on field_quote_pattern_negation). No field name quoting is done if not set.
    field_quote_pattern : ClassVar[Pattern] = re.compile(r"(?i)(^(abort|absolute|access|action|add|admin|after|aggregate|all|also|alter|always|analyse|analyze|and|anti|any|array|as|asc|asof|assertion|assignment|asymmetric|at|attach|attribute|authorization|backward|before|begin|between|bigint|binary|bit|boolean|both|by|cache|call|called|cascade|cascaded|case|cast|catalog|centuries|century|chain|char|character|characteristics|check|checkpoint|class|close|cluster|coalesce|collate|collation|column|columns|comment|comments|commit|committed|compression|concurrently|configuration|conflict|connection|constraint|constraints|content|continue|conversion|copy|cost|create|cross|csv|cube|current|cursor|cycle|data|database|day|days|deallocate|dec|decade|decades|decimal|declare|default|defaults|deferrable|deferred|definer|delete|delimiter|delimiters|depends|desc|describe|detach|dictionary|disable|discard|distinct|do|document|domain|double|drop|each|else|enable|encoding|encrypted|end|enum|escape|event|except|exclude|excluding|exclusive|execute|exists|explain|export|export_state|extension|extensions|external|extract|false|family|fetch|filter|first|float|following|for|force|foreign|forward|freeze|from|full|function|functions|generated|glob|global|grant|granted|group|grouping|grouping_id|groups|handler|having|header|hold|hour|hours|identity|if|ignore|ilike|immediate|immutable|implicit|import|in|include|including|increment|index|indexes|inherit|inherits|initially|inline|inner|inout|input|insensitive|insert|install|instead|int|integer|intersect|interval|into|invoker|is|isnull|isolation|join|json|key|label|language|large|last|lateral|leading|leakproof|left|level|like|limit|listen|load|local|location|lock|locked|logged|macro|map|mapping|match|materialized|maxvalue|method|microsecond|microseconds|millennia|millennium|millisecond|milliseconds|minute|minutes|minvalue|mode|month|months|move|name|names|national|natural|nchar|new|next|no|none|not|nothing|notify|notnull|nowait|null|nullif|nulls|numeric|object|of|off|offset|oids|old|on|only|operator|option|options|or|order|ordinality|others|out|outer|over|overlaps|overlay|overriding|owned|owner|parallel|parser|partial|partition|passing|password|percent|persistent|pivot|pivot_longer|pivot_wider|placing|plans|policy|position|positional|pragma|preceding|precision|prepare|prepared|preserve|primary|prior|privileges|procedural|procedure|program|publication|qualify|quarter|quarters|quote|range|read|real|reassign|recheck|recursive|ref|references|referencing|refresh|reindex|relative|release|rename|repeatable|replace|replica|reset|respect|restart|restrict|returning|returns|revoke|right|role|rollback|rollup|row|rows|rule|sample|savepoint|schema|schemas|scope|scroll|search|second|seconds|secret|security|select|semi|sequence|sequences|serializable|server|session|set|setof|sets|share|show|similar|simple|skip|smallint|snapshot|some|sql|stable|standalone|start|statement|statistics|stdin|stdout|storage|stored|strict|strip|struct|subscription|substring|summarize|symmetric|sysid|system|table|tables|tablesample|tablespace|temp|template|temporary|text|then|ties|time|timestamp|to|trailing|transaction|transform|treat|trigger|trim|true|truncate|trusted|try_cast|type|types|unbounded|uncommitted|unencrypted|union|unique|unknown|unlisten|unlogged|unpivot|until|update|use|user|using|vacuum|valid|validate|validator|value|values|varchar|variadic|varying|verbose|version|view|views|virtual|volatile|week|weeks|when|where|whitespace|window|with|within|without|work|wrapper|write|xml|xmlattributes|xmlconcat|xmlelement|xmlexists|xmlforest|xmlnamespaces|xmlparse|xmlpi|xmlroot|xmlserialize|xmltable|year|years|yes|zone)$)|.*[^\w]")   # Quote field names if this pattern (doesn't) matches, depending on field_quote_pattern_negation. Field name is always quoted if pattern is not set.
    # $ duckdb -json -c 'select keyword_name from duckdb_keywords()' | jq -r .[].keyword_name | tr '\n' '|'
    field_quote_pattern_negation : ClassVar[bool] = False            # Negate field_quote_pattern result. Field name is quoted if pattern doesn't matches if set to True (default).

    ### Escaping
    field_escape : ClassVar[str] = "`"               # Character to escape particular parts defined in field_escape_pattern.
    field_escape_quote : ClassVar[bool] = True        # Escape quote string defined in field_quote
    field_escape_pattern : ClassVar[Pattern] = None   # All matches of this pattern are prepended with the string contained in field_escape.

    ## Values
    str_quote       : ClassVar[str] = "'"     # string quoting character (added as escaping character)
    escape_char     : ClassVar[str] = "\\"    # Escaping character for special characters inside string
    wildcard_multi  : ClassVar[str] = "%"     # Character used as multi-character wildcard
    wildcard_single : ClassVar[str] = "_"     # Character used as single-character wildcard
    add_escaped     : ClassVar[str] = ""    # Characters quoted in addition to wildcards and string quote
    filter_chars    : ClassVar[str] = ""      # Characters filtered
    bool_values     : ClassVar[Dict[bool, str]] = {   # Values to which boolean values are mapped.
        True: "1", # TODO needs testing
        False: "0",
    }

    # Regular expressions
    # Regular expression query as format string with placeholders {field}, {regex}, {flag_x} where x
    # is one of the flags shortcuts supported by Sigma (currently i, m and s) and refers to the
    # token stored in the class variable re_flags.
    re_expression : ClassVar[str] = "{field} ~ '{regex}'"
    re_escape_char : ClassVar[str] = ""               # Character used for escaping in regular expressions
    re_escape : ClassVar[Tuple[str]] = (".")               # List of strings that are escaped
    re_escape_escape_char : bool = False                # If True, the escape character is also escaped
    re_flag_prefix : bool = True                        # If True, the flags are prepended as (?x) group at the beginning of the regular expression, e.g. (?i). If this is not supported by the target, it should be set to False.
    # Mapping from SigmaRegularExpressionFlag values to static string templates that are used in
    # flag_x placeholders in re_expression template.
    # By default, i, m and s are defined. If a flag is not supported by the target query language,
    # remove it from re_flags or don't define it to ensure proper error handling in case of appearance.
    re_flags : Dict[SigmaRegularExpressionFlag, str] = {
        SigmaRegularExpressionFlag.IGNORECASE: "i",
        SigmaRegularExpressionFlag.MULTILINE : "m",
        SigmaRegularExpressionFlag.DOTALL    : "s",
    }

    # Case sensitive string matching expression. String is quoted/escaped like a normal string.
    # Placeholders {field} and {value} are replaced with field name and quoted/escaped string.
    case_sensitive_match_expression : ClassVar[str] = "{field} LIKE {value}"
    # Case sensitive string matching operators similar to standard string matching. If not provided,
    # case_sensitive_match_expression is used.
    #case_sensitive_startswith_expression : ClassVar[str] = "{field} casematch_startswith {value}"
    #case_sensitive_endswith_expression   : ClassVar[str] = "{field} casematch_endswith {value}"
    #case_sensitive_contains_expression   : ClassVar[str] = "{field} casematch_contains {value}"

    # CIDR expressions: define CIDR matching if backend has native support. Else pySigma expands
    # CIDR values into string wildcard matches.
    cidr_expression : ClassVar[Optional[str]] = None

    # Numeric comparison operators
    compare_op_expression : ClassVar[str] = "{field}{operator}{value}"  # Compare operation query as format string with placeholders {field}, {operator} and {value}
    # Mapping between CompareOperators elements and strings used as replacement for {operator} in compare_op_expression
    compare_operators : ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT  : "<",
        SigmaCompareExpression.CompareOperators.LTE : "<=",
        SigmaCompareExpression.CompareOperators.GT  : ">",
        SigmaCompareExpression.CompareOperators.GTE : ">=",
    }

    # Expression for comparing two event fields
    field_equals_field_expression : ClassVar[Optional[str]] = "{field1} = {field2}"  # Field comparison expression with the placeholders {field1} and {field2} corresponding to left field and right value side of Sigma detection item
    field_equals_field_escaping_quoting : Tuple[bool, bool] = (True, True)   # If regular field-escaping/quoting is applied to field1 and field2. A custom escaping/quoting can be implemented in the convert_condition_field_eq_field_escape_and_quote method.

    # Null/None expressions
    field_null_expression : ClassVar[str] = "{field} IS NULL"          # Expression for field has null value as format string with {field} placeholder for field name

    # Field existence condition expressions.
    field_exists_expression : ClassVar[str] = "{field} IS NOT NULL"             # Expression for field existence as format string with {field} placeholder for field name
    field_not_exists_expression : ClassVar[str] = "{field} IS NULL"      # Expression for field non-existence as format string with {field} placeholder for field name. If not set, field_exists_expression is negated with boolean NOT.

    # Field value in list, e.g. "field in (value list)" or "field containsall (value list)"
    convert_or_as_in : ClassVar[bool] = False                     # Convert OR as in-expression
    convert_and_as_in : ClassVar[bool] = False                    # Convert AND as in-expression
    #in_expressions_allow_wildcards : ClassVar[bool] = True       # Values in list can contain wildcards. If set to False (default) only plain values are converted into in-expressions.
    #field_in_list_expression : ClassVar[str] = "{field} {op} ({list})"  # Expression for field in list of values as format string with placeholders {field}, {op} and {list}
    #or_in_operator : ClassVar[str] = "in"               # Operator used to convert OR into in-expressions. Must be set if convert_or_as_in is set
    #and_in_operator : ClassVar[str] = "contains-all"    # Operator used to convert AND into in-expressions. Must be set if convert_and_as_in is set
    #list_separator : ClassVar[str] = ", "               # List element separator

    # Value not bound to a field
    #unbound_value_str_expression : ClassVar[str] = "raw ILIKE {value}" # Expression for string value not bound to a field as format string with placeholder {value}
    #unbound_value_num_expression : ClassVar[str] = "raw ILIKE {value}"     # Expression for number value not bound to a field as format string with placeholder {value}
    #unbound_value_re_expression : ClassVar[str] = "raw REGEXP {value}"   # Expression for regular expression not bound to a field as format string with placeholder {value} and {flag_x} as described for re_expression

    # Query finalization: appending and concatenating deferred query part
    #deferred_start : ClassVar[str] = "\n| "               # String used as separator between main query and deferred parts
    #deferred_separator : ClassVar[str] = "\n| "           # String used to join multiple deferred query parts
    #deferred_only_query : ClassVar[str] = "*"            # String used as query if final query only contains deferred expression

    # Table name, passed as the Backend config option `table_name`
    table_name : ClassVar[str] = ""

    def convert_condition_field_eq_val_str(self, cond : ConditionFieldEqualsValueExpression, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of field = string value expressions"""
        try:
            expr = "{field} ILIKE {value}"
            field = cond.field
            value = cond.value

            is_endswith = (
                value.startswith(SpecialChars.WILDCARD_MULTI)
                and not value[1:].contains_special()
            )

            # Are there any escaped wildcards in the value?
            if "%" in value or "_" in value:
                # Specify `\` as an escape character for `_` and `%` in this LIKE condition
                expr += r" ESCAPE '\'"

            # Convert/quote field and value
            converted_field = self.escape_and_quote_field(cond.field)
            converted_value = self.convert_value_str(value, state)

            return expr.format(field=converted_field, value=converted_value)
        except TypeError:       # pragma: no cover
            raise NotImplementedError("Field equals string value expressions with strings are not supported by the backend.")

    def convert_condition_val_str(self, cond : ConditionValueExpression, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of value-only strings."""
        raise NotImplementedError("Keyword expressions are not supported by the backend.")

        expr = self.unbound_value_str_expression
        value = cond.value

        if not value.startswith(SpecialChars.WILDCARD_MULTI):
            value = SpecialChars.WILDCARD_MULTI + value

        if not value.endswith(SpecialChars.WILDCARD_MULTI):
            value = value + SpecialChars.WILDCARD_MULTI

        # Are there any escaped wildcards in the value?
        if "%" in value or "_" in value:
            # Specify `\` as an escape character for `_` and `%` in this LIKE condition
            expr += r" ESCAPE '\'"

        converted_value = self.convert_value_str(value, state)
        return expr.format(value=converted_value)

    def convert_condition_val_num(self, cond : ConditionValueExpression, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of value-only numbers."""
        return self.convert_condition_val_str(ConditionValueExpression(value=SigmaString(str(cond.value))), state)

    def convert_value_str(self, s: SigmaString, state: ConversionState) -> str:
        """Convert a SigmaString into a plain string which can be used in query."""
        converted = s.convert(
            self.escape_char,
            self.wildcard_multi,
            self.wildcard_single,
            self.add_escaped, # `self.str_quote` was removed from this line; in DuckDB, `'` is not escaped in the same way as wildcards
            self.filter_chars,
        )

        # DuckDB escapes `'` as `''`
        converted = converted.replace("'", "''")

        return self.quote_string(converted)

    def wrap_query(self, rule: SigmaRule, query: str):
        # Naively assumes all events are located in a single table
        return f"SELECT * FROM {self.table_name} WHERE {query}"

    def rule_to_tactics(self, rule: SigmaRule) -> List[str]:
        tactic_labels = {
            'reconnaissance': "Reconnaissance",
            'resource_development': "Resource Development",
            'initial_access': "Initial Access",
            'execution': "Execution",
            'persistence': "Persistence",
            'privilege_escalation': "Privilege Escalation",
            'defense_evasion': "Defense Evasion",
            'credential_access': "Credential Access",
            'discovery': "Discovery",
            'lateral_movement': "Lateral Movement",
            'collection': "Collection",
            'command_and_control': "Command and Control",
            'exfiltration': "Exfiltration",
            'impact': "Impact",
        }

        tactics = []
        for tag in rule.tags:
            if tag.namespace == "attack" and tag.name in tactic_labels:
                name = tactic_labels[tag.name]
                if not name in tactics:
                    tactics.append(name)

        return tactics

    def finalize_query_default(self, rule: SigmaRule, query: str, index: int, state: ConversionState) -> str:
        return self.wrap_query(rule, query)

    def finalize_query_json(self, rule: SigmaRule, query: str, index: int, state: ConversionState) -> Dict:
        out = rule.to_dict()
        out['query'] = self.wrap_query(rule, query)
        out['tactics'] = self.rule_to_tactics(rule)
        return out

    def finalize_output_json(self, queries: List[Dict]) -> List[Dict]:
        return queries
