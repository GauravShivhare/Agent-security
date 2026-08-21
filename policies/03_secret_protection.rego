package agentsec

# Violation: Secrets in tool arguments
violations[msg] {
    event := input.events[_]
    event.type == "tool_call"
    arg_value := event.arguments[_]
    contains_secret(arg_value)
    msg := {
        "message": sprintf("Secret detected in tool '%s' argument", [event.tool]),
        "severity": "critical",
        "event_ref": event,
        "rule": "secret_in_tool_args"
    }
}

# Warning: Environment variable access
warnings[msg] {
    event := input.events[_]
    event.type == "tool_call"
    arg_value := event.arguments[_]
    contains_env_access(arg_value)
    msg := {
        "message": sprintf("Environment variable access in tool '%s'", [event.tool]),
        "severity": "medium",
        "event_ref": event,
        "rule": "env_var_access"
    }
}

contains_secret(value) {
    secret_patterns := [
        "sk-[a-zA-Z0-9]{32,}",
        "AKIA[0-9A-Z]{16}",
        "api[_-]?key",
        "secret[_-]?key",
        "password",
        "token",
        "private[_-]?key",
    ]
    str_val := sprintf("%v", [value])
    lower := lower(str_val)
    some pattern in secret_patterns { regex.match(pattern, lower) }
}

contains_env_access(value) {
    str_val := sprintf("%v", [value])
    contains(str_val, "$") or contains(str_val, "${")
}
