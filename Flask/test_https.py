from flask import Flask, jsonify
import secrets
from flask_restful import Api, Resource
from datetime import datetime
import random
import string

app = Flask(__name__)

@app.route('/')
def home():
    return "Hello World!"

@app.route("/passwd")
def passwd():
    #now = datetime.now()
    my_chars="0123456789ABCD"
    result = ''.join(random.sample(my_chars, 6))
    #get_code = scrambler #unique_code_generator(6)
    #print (get_code)
    #return {"Password": get_code, "Date_Time": now.strftime("%m/%d/%Y, %H:%M:%S") }
    return {"Password" : result}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, ssl_context="adhoc")
