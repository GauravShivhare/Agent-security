package agentsec

# Violation: Email sent to external/unauthorized domain
violations[msg] {
    event := input.events[_]
    event.type == "tool_call"
    event.tool == "send_email"
    event.arguments.to
    not is_authorized_domain(event.arguments.to)
    msg := {
        "message": sprintf("Unauthorized email to domain: %s", [event.arguments.to]),
        "severity": "high",
        "event_ref": event,
        "rule": "unauthorized_email_domain"
    }
}

# Violation: Email with sensitive data attachments
violations[msg] {
    event := input.events[_]
    event.type == "tool_call"
    event.tool == "send_email"
    attachment := event.arguments.attachments[_]
    contains_sensitive(attachment)
    msg := {
        "message": sprintf("Sensitive data in email attachment: %s", [attachment]),
        "severity": "critical",
        "event_ref": event,
        "rule": "sensitive_email_attachment"
    }
}

# Warning: Multiple rapid tool calls (potential abuse)
warnings[msg] {
    tool_calls := [e | e := input.events[_]; e.type == "tool_call"]
    count(tool_calls) > 10
    msg := {
        "message": sprintf("High tool call count: %d (potential abuse)", [count(tool_calls)]),
        "severity": "medium",
        "rule": "high_tool_call_rate"
    }
}

# Helper: Check if domain is authorized
is_authorized_domain(email) {
    authorized := {"company.example", "internal.example", "trusted-partner.example"}
    domain := split(email, "@")[1]
    domain in authorized
}

# Helper: Check if filename contains sensitive patterns
contains_sensitive(filename) {
    sensitive := ["password", "secret", "key", "token", "ssn", "credit", "customer", "database", "export", "dump", "backup", "pii"]
    lower := lower(filename)
    some sensitive_pattern in sensitive { contains(lower, sensitive_pattern) }
}
