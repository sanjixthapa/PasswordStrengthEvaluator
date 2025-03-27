import secrets


def generate_suggestions(password, entropy, evaluator):
    """Generate suggestions to improve password strength"""
    suggestions = []

    if len(password) < 12:
        suggestions.append(f"Increase length from {len(password)} to at least 12 characters")

    missing = []
    if not any(c in evaluator.UPPERCASE for c in password):
        missing.append("uppercase letters")
    if not any(c in evaluator.DIGITS for c in password):
        missing.append("digits")
    if not any(c in evaluator.SPECIAL for c in password):
        missing.append("special characters")

    if missing:
        suggestions.append(f"Add {', '.join(missing)} to increase complexity")

    return suggestions


def generate_strong_password(length, evaluator):
    """Generate a strong password with high entropy"""
    while True:
        password = ''.join(secrets.choice(evaluator.ALL_CHARS) for _ in range(length))
        entropy = evaluator.calculate_entropy(password)
        if entropy >= 80:
            return password
