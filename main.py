# main.py

from policy import PasswordPolicy
from evaluator import PasswordStrengthEvaluator
from generator import generate_strong_password

def main():
    policy = PasswordPolicy(min_length=16)
    evaluator = PasswordStrengthEvaluator(policy)

    print("Password Strength Evaluator")
    print("---------------------------")

    while True:
        pwd = input("\nEnter a password (or 'q' to quit): ")
        if pwd.lower() == 'q':
            break

        result = evaluator.evaluate(pwd)

        print("\n=== Evaluation ===")
        print(f"Strength: {result['strength']}")
        print(f"Entropy: {result['entropy']} bits")
        print(f"Message: {result['message']}")

        if result['suggestions']:
            print("Suggestions:")
            for s in result['suggestions']:
                print(f"- {s}")

        example = generate_strong_password(16, evaluator)
        print(f"\n Example strong password: {example}")

if __name__ == "__main__":
    main()
