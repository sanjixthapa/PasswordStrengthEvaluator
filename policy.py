# policy.py

class PasswordPolicy:
    def __init__(self, min_length=16, require_upper=True, require_lower=True,
                 require_digits=True, require_special=True, disallowed_patterns=None):
        self.min_length = min_length
        self.require_upper = require_upper
        self.require_lower = require_lower
        self.require_digits = require_digits
        self.require_special = require_special
