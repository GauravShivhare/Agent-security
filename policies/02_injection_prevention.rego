package agentsec

# Violation: SQL injection patterns in database queries
violations[msg] {
    event := input.events[_]
    event.type == "tool_call"
    event.tool == "query_database"
    query := event.arguments.query
    contains_sql_injection(query)
    msg := {
        "message": sprintf("SQL injection detected in query: %s", [query]),
        "severity": "critical",
        "event_ref": event,
        "rule": "sql_injection"
    }
}

# Violation: Path traversal in file operations
violations[msg] {
    event := input.events[_]
    event.type == "tool_call"
    event.tool == "read_file"
    path := event.arguments.path
    contains_path_traversal(path)
    msg := {
        "message": sprintf("Path traversal attempt: %s", [path]),
        "severity": "high",
        "event_ref": event,
        "rule": "path_traversal"
    }
}

contains_sql_injection(query) {
    patterns := [
        "OR\s+'1'='1",
        "UNION\s+SELECT",
        "DROP\s+TABLE",
        "INSERT\s+INTO",
        "DELETE\s+FROM",
        "--",
        ";\s*--",
        "EXEC\s*\(",
        "xp_cmdshell",
    ]
    lower := lower(query)
    some pattern in patterns { regex.match(pattern, lower) }
}

contains_path_traversal(path) {
    patterns := ["../", "..\\", "/etc/passwd", "/etc/shadow", "C:\\Windows", "~/.ssh"]
    some pattern in patterns { contains(path, pattern) }
}
