"""
attacks/ — the vulnerability-class plugin matrix.

Importing this package registers every built-in plugin (each module calls
attacks.base.register at import time). The engine then runs
attacks.base.all_plugins() against each discovered endpoint.
"""
from attacks import (          # noqa: F401  (imported for registration side-effects)
    broken_auth,
    idor,
    mass_assignment,
    sqli,
    xss,
    stored_xss,
    path_traversal,
    authz_matrix,
    web_extra,      # cors, security_headers, open_redirect, ssti, command_injection, secrets
    jwt_attacks,
    graphql,
)
