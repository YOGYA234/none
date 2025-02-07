# inits
from flask import send_from_directory

def setup_caching(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

def setup_static_files(filename):
  return send_from_directory('static', filename)

