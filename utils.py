# utils.py

import string

LOWERCASE = string.ascii_lowercase
UPPERCASE = string.ascii_uppercase
DIGITS = string.digits
SPECIAL = string.punctuation
ALL_CHARS = LOWERCASE + UPPERCASE + DIGITS + SPECIAL

COMMON_PATTERNS = [
    '123456', 'password', 'qwerty', '111111',
    'abc123', 'password1', 'admin', 'welcome'
]
