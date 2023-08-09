from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule
from sigma.conversion.base import TextQueryBackend
from sigma.conditions import ConditionItem, ConditionAND, ConditionOR, ConditionNOT
from sigma.processing.pipeline import ProcessingPipeline
from sigma.types import SigmaCompareExpression, SigmaRegularExpression, SigmaRegularExpressionFlag
from sigma.pipelines.kusto import kusto_pipeline
import sigma
import re
from typing import ClassVar, Dict, Tuple, Pattern, List, Any, Optional

# See the pySigma documentation for further infromation:
# https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html

class KustoBackend(TextQueryBackend):
    """Kusto backend."""

    def __init__(
        self,
        processing_pipeline: Optional[ProcessingPipeline] = None,
        collect_errors: bool = False,
        table_name : str = None,
        raw_field : str = None,
    ):
        super().__init__(processing_pipeline, collect_errors)

        self.table_name = table_name
        if not raw_field:
            raise RuntimeError("The backend option `raw_field` must be set")

        raw_field = self.escape_and_quote_field(raw_field)
        self.unbound_value_str_expression : str = self.contains_expression.replace("{field}", raw_field)  # Expression for string value not bound to a field as format string with placeholder {value}
        self.unbound_value_num_expression : str = raw_field + " contains '{value}'"  # Expression for number value not bound to a field as format string with placeholder {value}
        self.unbound_value_re_expression : str = self.re_expression.replace("{field}", raw_field)  # Expression for regular expression not bound to a field as format string with placeholder {value} and {flag_x} as described for re_expression

    # Operator precedence: tuple of Condition{AND,OR,NOT} in order of precedence.
    # The backend generates grouping if required
    name : ClassVar[str] = "Kusto Backend"
    formats : Dict[str, str] = {
        "default": "Plain Kusto queries",
        "json": "Rule and query as json lines",
    }
    requires_pipeline : bool = False
    backend_processing_pipeline : ClassVar[ProcessingPipeline] = kusto_pipeline()

    precedence : ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (ConditionNOT, ConditionAND, ConditionOR)
    group_expression : ClassVar[str] = "({expr})"   # Expression for precedence override grouping as format string with {expr} placeholder

    # Generated query tokens
    token_separator : str = " "     # separator inserted between all boolean operators
    or_token : ClassVar[str] = "or"
    and_token : ClassVar[str] = "and"
    not_token : ClassVar[str] = "not"
    eq_token : ClassVar[str] = " =~ "  # Token inserted between field and value (without separator)

    # String output
    ## Fields
    ### Quoting
    field_quote : ClassVar[str] = "'"                               # Character used to quote field characters if field_quote_pattern matches (or not, depending on field_quote_pattern_negation). No field name quoting is done if not set.
    field_quote_pattern : ClassVar[Pattern] = re.compile("^\\w+$")   # Quote field names if this pattern (doesn't) matches, depending on field_quote_pattern_negation. Field name is always quoted if pattern is not set.
    field_quote_pattern_negation : ClassVar[bool] = True            # Negate field_quote_pattern result. Field name is quoted if pattern doesn't matches if set to True (default).

    ### Escaping
    field_escape : ClassVar[str] = "\\"               # Character to escape particular parts defined in field_escape_pattern.
    field_escape_quote : ClassVar[bool] = True        # Escape quote string defined in field_quote
    field_escape_pattern : ClassVar[Pattern] = re.compile("\\s")   # All matches of this pattern are prepended with the string contained in field_escape.

    ## Values
    str_quote       : ClassVar[str] = "'"     # string quoting character (added as escaping character)
    escape_char     : ClassVar[str] = "\\"    # Escaping character for special characrers inside string
    wildcard_multi  : ClassVar[str] = "*"     # Character used as multi-character wildcard
    wildcard_single : ClassVar[str] = "*"     # Character used as single-character wildcard
    add_escaped     : ClassVar[str] = "\\"    # Characters quoted in addition to wildcards and string quote
    filter_chars    : ClassVar[str] = ""      # Characters filtered
    bool_values     : ClassVar[Dict[bool, str]] = {   # Values to which boolean values are mapped.
        True: "true", # TODO
        False: "false",
    }

    # String matching operators. if none is appropriate eq_token is used.
    startswith_expression : ClassVar[str] = "{field} startswith {value}"
    endswith_expression   : ClassVar[str] = "{field} endswith {value}"
    contains_expression   : ClassVar[str] = "{field} contains {value}"
    wildcard_match_expression : ClassVar[str] = "{field} contains {value}"      # Special expression if wildcards can't be matched with the eq_token operator

    # Regular expressions
    # Regular expression query as format string with placeholders {field}, {regex}, {flag_x} where x
    # is one of the flags shortcuts supported by Sigma (currently i, m and s) and refers to the
    # token stored in the class variable re_flags.
    re_expression : ClassVar[str] = "{field} matches regex @'{regex}'" # TODO prepend (?i)?
    re_escape_char : ClassVar[str] = "\\"               # Character used for escaping in regular expressions
    re_escape : ClassVar[Tuple[str]] = ()               # List of strings that are escaped
    re_escape_escape_char : bool = True                 # If True, the escape character is also escaped
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
    case_sensitive_match_expression : ClassVar[str] = "{field} casematch {value}"
    # Case sensitive string matching operators similar to standard string matching. If not provided,
    # case_sensitive_match_expression is used.
    case_sensitive_startswith_expression : ClassVar[str] = "{field} startswith_cs {value}"
    case_sensitive_endswith_expression   : ClassVar[str] = "{field} endswith_cs {value}"
    case_sensitive_contains_expression   : ClassVar[str] = "{field} contains_cs {value}"

    # cidr expressions
    cidr_expression : ClassVar[Optional[str]] = "ipv4_is_in_range({field}, '{network}/{prefixlen}')" # CIDR expression query as format string with placeholders {field}, {value} (the whole CIDR value), {network} (network part only), {prefixlen} (length of network mask prefix) and {netmask} (CIDR network mask only)

    # Numeric comparison operators
    compare_op_expression : ClassVar[str] = "{field} {operator} {value}"  # Compare operation query as format string with placeholders {field}, {operator} and {value}
    # Mapping between CompareOperators elements and strings used as replacement for {operator} in compare_op_expression
    compare_operators : ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT  : "<",
        SigmaCompareExpression.CompareOperators.LTE : "<=",
        SigmaCompareExpression.CompareOperators.GT  : ">",
        SigmaCompareExpression.CompareOperators.GTE : ">=",
    }

    # Expression for comparing two event fields
    field_equals_field_expression : ClassVar[Optional[str]] = None  # Field comparison expression with the placeholders {field1} and {field2} corresponding to left field and right value side of Sigma detection item
    field_equals_field_escaping_quoting : Tuple[bool, bool] = (True, True)   # If regular field-escaping/quoting is applied to field1 and field2. A custom escaping/quoting can be implemented in the convert_condition_field_eq_field_escape_and_quote method.

    # Null/None expressions
    field_null_expression : ClassVar[str] = "isempty({field})"          # Expression for field has null value as format string with {field} placeholder for field name

    # Field existence condition expressions.
    field_exists_expression : ClassVar[str] = "isnotempty({field})"             # Expression for field existence as format string with {field} placeholder for field name
    field_not_exists_expression : ClassVar[str] = "isempty({field})"      # Expression for field non-existence as format string with {field} placeholder for field name. If not set, field_exists_expression is negated with boolean NOT.

    # Field value in list, e.g. "field in (value list)" or "field containsall (value list)"
    convert_or_as_in : ClassVar[bool] = True                     # Convert OR as in-expression
    convert_and_as_in : ClassVar[bool] = False                    # Convert AND as in-expression
    in_expressions_allow_wildcards : ClassVar[bool] = False       # Values in list can contain wildcards. If set to False (default) only plain values are converted into in-expressions.
    field_in_list_expression : ClassVar[str] = "{field} {op} ({list})"  # Expression for field in list of values as format string with placeholders {field}, {op} and {list}
    or_in_operator : ClassVar[str] = "in~"   # Operator used to convert OR into in-expressions. Must be set if convert_or_as_in is set
    and_in_operator : ClassVar[str] = None   # Operator used to convert AND into in-expressions. Must be set if convert_and_as_in is set
    list_separator : ClassVar[str] = ", "    # List element separator

    # Value not bound to a field
    unbound_value_str_expression : str = None   # Expression for string value not bound to a field as format string with placeholder {value}
    unbound_value_num_expression : str = None     # Expression for number value not bound to a field as format string with placeholder {value}
    unbound_value_re_expression : str = None   # Expression for regular expression not bound to a field as format string with placeholder {value} and {flag_x} as described for re_expression

    # Query finalization: appending and concatenating deferred query part
    deferred_start : ClassVar[str] = "\n| "               # String used as separator between main query and deferred parts
    deferred_separator : ClassVar[str] = "\n| "           # String used to join multiple deferred query parts
    deferred_only_query : ClassVar[str] = "*"            # String used as query if final query only contains deferred expression

    # TODO: implement custom methods for query elements not covered by the default backend base.
    # Documentation: https://sigmahq-pysigma.readthedocs.io/en/latest/Backends.html

    # Name of table to search in
    table_name : Optional[str] = None

    # Field that contains raw log message, to match keyword conditions against
    raw_field : str = None

    def escape_and_quote_field(self, field_name : str):
        quoted_field = super().escape_and_quote_field(field_name)

        # Was the field quoted?
        if quoted_field.startswith(self.field_quote) and quoted_field.endswith(self.field_quote):
            # Also wrap it in brackets
            quoted_field = "[" + quoted_field + "]"

        return quoted_field

    def wrap_query(self, query : str) -> str:
        if self.table_name:
            query = f"{self.table_name} | where {query}"

        return query

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
        return self.wrap_query(query)

    def finalize_query_json(self, rule: SigmaRule, query: str, index: int, state: ConversionState) -> Dict:
        out = rule.to_dict()
        out['query'] = self.wrap_query(query)
        out['tactics'] = self.rule_to_tactics(rule)
        return out

    def finalize_output_json(self, queries: List[Dict]) -> List[Dict]:
        return queries
