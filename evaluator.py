# evaluator.py

import math
import re
from utils import LOWERCASE, UPPERCASE, DIGITS, SPECIAL, COMMON_PATTERNS

class PasswordStrengthEvaluator:
    def __init__(self, policy):
        self.policy = policy

    def calculate_entropy(self, password):
        pool = 0
        if any(c in LOWERCASE for c in password): pool += len(LOWERCASE)
        if any(c in UPPERCASE for c in password): pool += len(UPPERCASE)
        if any(c in DIGITS for c in password): pool += len(DIGITS)
        if any(c in SPECIAL for c in password): pool += len(SPECIAL)
        pool = pool or len(LOWERCASE)
        return len(password) * math.log2(pool)

    def check_common_patterns(self, password):
        if password.lower() in COMMON_PATTERNS:
            return True, "Common password"
        if re.match(r'^csc_\d+$', password, re.IGNORECASE):
            return True, "Default CS account password detected."
        return False, None

    def check_policy(self, password):
        errors = []
        if len(password) < self.policy.min_length:
            errors.append(f"Minimum length: {self.policy.min_length}")
        if self.policy.require_upper and not any(c.isupper() for c in password):
            errors.append("Needs at least one uppercase letter.")
        if self.policy.require_lower and not any(c.islower() for c in password):
            errors.append("Needs at least one lowercase letter.")
        if self.policy.require_digits and not any(c.isdigit() for c in password):
            errors.append("Needs at least one digit.")
        if self.policy.require_special and not any(c in SPECIAL for c in password):
            errors.append("Needs at least one special character.")
        for pattern in self.policy.disallowed_patterns:
            if re.search(pattern, password):
                errors.append("Contains disallowed pattern.")
        return errors

    def evaluate(self, password):
        if not password:
            return {'strength': 'Very Weak', 'entropy': 0, 'message': 'Empty password', 'suggestions': []}

        entropy = self.calculate_entropy(password)
        is_common, reason = self.check_common_patterns(password)

        if is_common:
            return {'strength': 'Very Weak', 'entropy': entropy, 'message': reason, 'suggestions': ['Use a unique password.']}

        suggestions = self.check_policy(password)

        if entropy < 28:
            strength = 'Very Weak'
            msg = 'Very easy to guess.'
        elif entropy < 36:
            strength = 'Weak'
            msg = 'Still guessable.'
        elif entropy < 60:
            strength = 'Moderate'
            msg = 'Somewhat secure.'
        elif entropy < 100:
            strength = 'Strong'
            msg = 'Secure.'
        else:
            strength = 'Very Strong'
            msg = 'Very secure.'

        if suggestions:
            strength = 'Weak'
            msg = 'Does not meet policy.'

        return {
            'strength': strength,
            'entropy': round(entropy, 2),
            'message': msg,
            'suggestions': suggestions
        }
