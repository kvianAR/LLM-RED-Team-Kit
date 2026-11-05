"""Small declarative substitutions without executable template expressions."""

import re


def render_message(message, principal, resource, session):
    values = {"principal": principal, "resource": resource, "session": session}

    def replace(match):
        name = match.group(1).strip()
        if name not in values:
            raise ValueError("Unknown template variable; protected canaries cannot be interpolated")
        return values[name]

    rendered = re.sub(r"\{\{([^{}]+)\}\}", replace, message)
    if "{{" in rendered or "}}" in rendered or len(rendered) > 16384:
        raise ValueError("Malformed or oversized message template")
    return rendered
