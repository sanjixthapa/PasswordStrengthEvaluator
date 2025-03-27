import math
import string
import secrets
from collections import Counter


class PasswordStrengthEvaluator:
    def __init__(self):
        # Define character sets
        self.LOWERCASE = string.ascii_lowercase
        self.UPPERCASE = string.ascii_uppercase
        self.DIGITS = string.digits
        self.SPECIAL = string.punctuation
        self.ALL_CHARS = self.LOWERCASE + self.UPPERCASE + self.DIGITS + self.SPECIAL

        # Common password patterns to check against
        self.COMMON_PATTERNS = [
            '123456', 'password', 'qwerty', '111111',
            'abc123', 'password1', 'admin', 'welcome'
        ]

        # Common substitutions (e.g., p@ssword)
        self.SUBSTITUTIONS = {
            'a': ['@', '4'],
            'b': ['8'],
            'e': ['3'],
            'g': ['9', '6'],
            'i': ['1', '!'],
            'l': ['1', '|'],
            'o': ['0'],
            's': ['5', '$'],
            't': ['7', '+']
        }

    def calculate_entropy(self, password):
        """Calculate password entropy in bits"""
        # Determine character pool size
        char_pool = 0
        has_lower = any(c in self.LOWERCASE for c in password)
        has_upper = any(c in self.UPPERCASE for c in password)
        has_digit = any(c in self.DIGITS for c in password)
        has_special = any(c in self.SPECIAL for c in password)

        if has_lower:
            char_pool += len(self.LOWERCASE)
        if has_upper:
            char_pool += len(self.UPPERCASE)
        if has_digit:
            char_pool += len(self.DIGITS)
        if has_special:
            char_pool += len(self.SPECIAL)

        # If no character sets detected, assume lowercase only
        if char_pool == 0:
            char_pool = len(self.LOWERCASE)

        # Calculate entropy
        entropy = len(password) * math.log2(char_pool)
        return entropy

    def check_common_patterns(self, password):
        """Check against common weak passwords and patterns"""
        lower_pwd = password.lower()

        # Check against common passwords
        if lower_pwd in self.COMMON_PATTERNS:
            return True, "Common password"

        # Check for keyboard walks (qwerty, etc.)
        for i in range(len(lower_pwd) - 3):
            substring = lower_pwd[i:i + 4]
            if (substring in 'qwertyuiop' or
                    substring in 'asdfghjkl' or
                    substring in 'zxcvbnm' or
                    substring in '1234567890'):
                return True, "Keyboard pattern"

        # Check for repeated characters
        if any(count > 3 for count in Counter(password).values()):
            return True, "Repeated characters"

        # Check for common substitutions
        for original, subs in self.SUBSTITUTIONS.items():
            for sub in subs:
                if sub in password:
                    # Check if this is part of a common substitution pattern
                    test_pwd = password.lower().replace(sub, original)
                    if test_pwd in self.COMMON_PATTERNS:
                        return True, "Common password with substitutions"

        return False, None

    def evaluate_strength(self, password):
        """Evaluate password strength and provide feedback"""
        if not password:
            return {
                'strength': 'Very Weak',
                'entropy': 0,
                'message': 'No password provided',
                'suggestions': []
            }

        entropy = self.calculate_entropy(password)
        is_common, common_reason = self.check_common_patterns(password)

        # Evaluate strength based on entropy and common patterns
        if is_common:
            strength = 'Very Weak'
            message = f"Password contains a {common_reason}"
        elif entropy < 28:
            strength = 'Very Weak'
            message = 'Extremely vulnerable to brute force attacks'
        elif entropy < 36:
            strength = 'Weak'
            message = 'Vulnerable to brute force attacks'
        elif entropy < 60:
            strength = 'Moderate'
            message = 'Somewhat resistant to brute force attacks'
        elif entropy < 100:
            strength = 'Strong'
            message = 'Resistant to brute force attacks'
        else:
            strength = 'Very Strong'
            message = 'Highly resistant to brute force attacks'

        # Generate suggestions for improvement
        suggestions = self.generate_suggestions(password, entropy)

        return {
            'strength': strength,
            'entropy': round(entropy, 2),
            'message': message,
            'suggestions': suggestions
        }

    def generate_suggestions(self, password, current_entropy):
        """Generate suggestions to improve password strength"""
        suggestions = []

        # Length suggestions
        if len(password) < 12:
            suggestions.append(f"Increase length from {len(password)} to at least 12 characters")

        # Character diversity suggestions
        char_types = []
        if any(c in self.LOWERCASE for c in password):
            char_types.append("lowercase")
        if any(c in self.UPPERCASE for c in password):
            char_types.append("uppercase")
        if any(c in self.DIGITS for c in password):
            char_types.append("digits")
        if any(c in self.SPECIAL for c in password):
            char_types.append("special")

        if len(char_types) < 3:
            missing = []
            if not any(c in self.UPPERCASE for c in password):
                missing.append("uppercase letters")
            if not any(c in self.DIGITS for c in password):
                missing.append("digits")
            if not any(c in self.SPECIAL for c in password):
                missing.append("special characters")
            suggestions.append(f"Add {', '.join(missing)} to increase complexity")

        # Show entropy impact of adding characters
        if len(password) < 16:
            sample_additions = [
                (1, secrets.choice(self.UPPERCASE)),
                (1, secrets.choice(self.SPECIAL)),
                (2, secrets.choice(self.UPPERCASE) + secrets.choice(self.DIGITS)),
                (3, secrets.choice(self.SPECIAL) + secrets.choice(self.DIGITS) + secrets.choice(self.UPPERCASE))
            ]

            entropy_changes = []
            for add_len, add_chars in sample_additions:
                new_pwd = password + add_chars
                new_entropy = self.calculate_entropy(new_pwd)
                entropy_change = new_entropy - current_entropy
                entropy_changes.append(
                    f"Adding {add_len} character(s): +{entropy_change:.1f} bits (e.g., add '{add_chars}')"
                )

            suggestions.append("Entropy can be significantly increased by adding characters:")
            suggestions.extend(entropy_changes)

        return suggestions

    def generate_strong_password(self, length=16):
        """Generate a strong password with high entropy"""
        while True:
            password = ''.join(secrets.choice(self.ALL_CHARS) for _ in range(length))
            entropy = self.calculate_entropy(password)
            is_common, _ = self.check_common_patterns(password)

            if not is_common and entropy >= 80:
                return password


def main():
    evaluator = PasswordStrengthEvaluator()

    print("Password Strength Evaluator")
    print("--------------------------")

    while True:
        password = input("\nEnter a password to evaluate (or 'q' to quit): ")
        if password.lower() == 'q':
            break

        result = evaluator.evaluate_strength(password)

        print("\n=== Evaluation Results ===")
        print(f"Strength: {result['strength']}")
        print(f"Entropy: {result['entropy']} bits")
        print(f"Analysis: {result['message']}")

        if result['suggestions']:
            print("\nSuggestions for improvement:")
            for suggestion in result['suggestions']:
                print(f"- {suggestion}")

        # Demonstrate entropy growth with length
        if len(password) < 20:
            print("\nEntropy growth demonstration:")
            for i in range(len(password), len(password) + 5):
                test_pwd = password + 'X' * (i - len(password))
                entropy = evaluator.calculate_entropy(test_pwd)
                print(f"{i} chars: {entropy:.1f} bits")

        # Show a generated strong password for comparison
        strong_pwd = evaluator.generate_strong_password()
        strong_entropy = evaluator.calculate_entropy(strong_pwd)
        print(f"\nExample strong password: {strong_pwd} ({strong_entropy:.1f} bits)")


if __name__ == "__main__":
    main()