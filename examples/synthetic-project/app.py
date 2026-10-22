"""Intentionally risky sample code. Do not use it in an application."""

import requests

SAMPLE_API_KEY = "synthetic_value_8f1a2b3c4d5e"


def load_user(user_id: str, user_expression: str, api_url: str):
    # Demonstration finding: interpolated SQL can mix data with query syntax.
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

    # Demonstration finding: evaluating dynamic input may execute code.
    eval(user_expression)

    # Demonstration finding: this disables certificate validation.
    requests.get(api_url, verify=False)
