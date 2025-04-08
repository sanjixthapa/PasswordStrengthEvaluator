# utils.py

import string

LOWERCASE = string.ascii_lowercase
UPPERCASE = string.ascii_uppercase
DIGITS = string.digits
SPECIAL = string.punctuation
ALL_CHARS = LOWERCASE + UPPERCASE + DIGITS + SPECIAL

COMMON_PATTERNS = [
    # Very common numbers
    '123456', '123456789', '12345678', '12345', '1234567', '111111', '000000',
    # Default / generic passwords
    'password', 'password1', 'admin', 'welcome', 'letmein', 'guest', 'test',
    # Keyboard patterns
    'qwerty', 'qwerty123', 'asdfgh', 'zxcvbnm', '1q2w3e4r', '123qwe',
    # Names and phrases
    'iloveyou', 'monkey', 'dragon', 'sunshine', 'football', 'baseball',
    # Years and dates
    '2020', '2021', '2022', '2023', '2024', '1984', '1990', '2000',
    # Local and CS-related patterns
    'oswego', 'laker', 'suny123', 'csc123', 'csc_101', 'csc_212', 'student', 'college',
    # Extra generics
    'abcd1234', 'welcome123', 'changeme', 'default', 'user', 'mypassword', 'superman'
]

