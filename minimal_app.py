from flask import Flask
import os

# Disable .env loading
os.environ["FLASK_SKIP_DOTENV"] = "1"

app = Flask(__name__)

@app.route('/')
def index():
    return "Hello World! DDoS Detection System is running."

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True) 