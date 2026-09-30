"""CWE → SecureLens vulnerability class, for normalising third-party scanner output."""

from __future__ import annotations

import re

CWE_TO_CLASS = {
    "CWE-89": "sql_injection", "CWE-564": "sql_injection", "CWE-943": "nosql_injection",
    "CWE-79": "xss", "CWE-80": "xss", "CWE-83": "xss",
    "CWE-78": "command_injection", "CWE-77": "command_injection", "CWE-88": "command_injection",
    "CWE-94": "code_injection", "CWE-95": "code_injection", "CWE-1336": "template_injection",
    "CWE-22": "path_traversal", "CWE-23": "path_traversal", "CWE-36": "path_traversal", "CWE-73": "path_traversal",
    "CWE-98": "file_inclusion", "CWE-918": "ssrf", "CWE-601": "open_redirect",
    "CWE-798": "hardcoded_secret", "CWE-259": "hardcoded_secret", "CWE-321": "hardcoded_secret",
    "CWE-327": "weak_cryptography", "CWE-328": "weak_cryptography", "CWE-326": "weak_cryptography",
    "CWE-916": "weak_cryptography", "CWE-330": "weak_randomness", "CWE-338": "weak_randomness",
    "CWE-295": "insecure_tls", "CWE-297": "insecure_tls", "CWE-319": "insecure_tls", "CWE-326-tls": "insecure_tls",
    "CWE-287": "insecure_authentication", "CWE-347": "insecure_authentication", "CWE-256": "insecure_authentication",
    "CWE-614": "insecure_authentication", "CWE-1004": "insecure_authentication", "CWE-352": "missing_csrf_protection",
    "CWE-639": "broken_authorization", "CWE-862": "broken_authorization", "CWE-863": "broken_authorization",
    "CWE-285": "broken_authorization", "CWE-434": "unsafe_file_handling", "CWE-377": "unsafe_file_handling",
    "CWE-732": "unsafe_file_handling", "CWE-502": "insecure_deserialization", "CWE-611": "xxe", "CWE-776": "xxe",
    "CWE-1321": "prototype_pollution", "CWE-1333": "redos", "CWE-200": "sensitive_data_exposure",
    "CWE-209": "dangerous_api", "CWE-489": "dangerous_api", "CWE-676": "dangerous_api", "CWE-942": "dangerous_api",
    "CWE-1395": "vulnerable_dependency", "CWE-120": "buffer_overflow", "CWE-121": "buffer_overflow",
    "CWE-122": "buffer_overflow", "CWE-787": "out_of_bounds", "CWE-125": "out_of_bounds", "CWE-129": "out_of_bounds",
    "CWE-416": "use_after_free", "CWE-415": "double_free", "CWE-134": "format_string", "CWE-190": "integer_overflow",
    "CWE-680": "integer_overflow", "CWE-362": "race_condition", "CWE-367": "race_condition",
    "CWE-90": "ldap_injection", "CWE-643": "xpath_injection", "CWE-917": "expression_injection",
    "CWE-1427": "prompt_injection", "CWE-1426": "llm_output_handling",
}

_CWE_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)


def normalise_cwe(value: str | int | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, int):
        return f"CWE-{value}"
    m = _CWE_RE.search(str(value))
    return f"CWE-{m.group(1)}" if m else (f"CWE-{value}" if str(value).isdigit() else None)


def class_for_cwes(cwes: list[str], default: str = "dangerous_api") -> str:
    for cwe in cwes:
        norm = normalise_cwe(cwe)
        if norm and norm in CWE_TO_CLASS:
            return CWE_TO_CLASS[norm]
    return default
