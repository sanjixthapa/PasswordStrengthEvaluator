# generator.py

import secrets
from utils import ALL_CHARS

def generate_strong_password(length, evaluator):
    while True:
        pwd = ''.join(secrets.choice(ALL_CHARS) for _ in range(length))
        if evaluator.calculate_entropy(pwd) >= 80 and not evaluator.check_common_patterns(pwd)[0]:
            return pwd
