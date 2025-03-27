from evaluator import PasswordStrengthEvaluator
from utils import generate_strong_password

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

        strong_pwd = generate_strong_password(16, evaluator)
        strong_entropy = evaluator.calculate_entropy(strong_pwd)
        print(f"\nExample strong password: {strong_pwd} ({strong_entropy:.1f} bits)")


if __name__ == "__main__":
    main()
