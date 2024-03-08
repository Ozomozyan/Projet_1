from flask import Flask

app = Flask(__name__)

@app.route('/')
def hello_world():
    return 'Im testing my regular tasks'

if __name__ == '__main__':
    app.run(debug=True)
