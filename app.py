from flask import Flask, render_template, request, jsonify
from policy import PasswordPolicy
from evaluator import PasswordStrengthEvaluator
from generator import generate_strong_password

app = Flask(__name__, static_folder='static')

# Initialize policy and evaluator
policy = PasswordPolicy(min_length=16)
evaluator = PasswordStrengthEvaluator(policy)

@app.route('/')
def index():
    """Render the main page"""
    return render_template('index.html')

@app.route('/evaluate', methods=['POST'])
def evaluate_password():
    """Evaluate password strength and return results"""
    password = request.form.get('password', '')
    result = evaluator.evaluate(password)
    return jsonify(result)

@app.route('/generate', methods=['GET'])
def generate_password():
    """Generate a strong password"""
    length = int(request.args.get('length', 16))
    password = generate_strong_password(length, evaluator)
    return jsonify({'password': password})

if __name__ == '__main__':
    app.run(debug=True)