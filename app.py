from flask import Flask, render_template, request
import os

from database import init_db
from detector.preprocess import clean_commands
from detector.sequence_builder import build_sequences
from detector.profiler import train_user
from detector.detector import detect

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

init_db()

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        user = request.form["user"]
        mode = request.form["mode"]
        file = request.files["history"]

        path = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(path)

        with open(path) as f:
            commands = f.readlines()

        cleaned = clean_commands(commands)
        sequences = build_sequences(cleaned)

        if mode == "train":
            train_user(user, sequences)
            return render_template("result.html", trained=True, user=user)

        alerts = detect(user, sequences)
        return render_template("result.html", alerts=alerts, user=user)

    return render_template("upload.html")

if __name__ == "__main__":
    app.run(debug=True)
