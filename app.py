from flask import Flask, render_template, request
import os
from werkzeug.utils import secure_filename  # ✅ NEW

from database import init_db
from detector.preprocess import clean_commands
from detector.sequence_builder import build_sequences
from detector.profiler import train_user
from detector.detector import detect

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"txt", "log","history"}  # ✅ NEW — only allow safe file types
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

init_db()

def allowed_file(filename):
    # ✅ Check extension
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return False
    return True

def is_text_file(filepath):
    # ✅ Check actual file content — not just extension
    try:
        with open(filepath, "r", errors="strict") as f:
            f.read(1024)  # try reading first 1KB as text
        return True
    except UnicodeDecodeError:
        return False
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        user = request.form.get("user", "").strip()
        mode = request.form.get("mode")
        file = request.files.get("history")

        # ✅ NEW — validate inputs
        if not user:
            return render_template("upload.html", error="Username is required.")

        if not file or file.filename == "":
            return render_template("upload.html", error="Please upload a file.")

        if not allowed_file(file.filename):
            return render_template("upload.html", error="Only .txt, .log, or .history files allowed.")

        filename = secure_filename(file.filename)
        path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(path)

        # ✅ NEW — reject binary files even if they have a .txt extension
        if not is_text_file(path):
            os.remove(path)  # delete the bad file
            return render_template("upload.html", error="File must be a plain text file.")

        with open(path, errors="replace") as f:
            commands = f.readlines()

        cleaned = clean_commands(commands)
        sequences = build_sequences(cleaned)

        if mode == "train":
            train_user(user, sequences)
            return render_template("result.html", trained=True, user=user)

        # ✅ NEW — user existence check before detection
        alerts, error = detect(user, sequences)
        if error:
            return render_template("upload.html", error=error)

        return render_template("result.html", alerts=alerts, user=user)

    return render_template("upload.html")

if __name__ == "__main__":
    app.run(debug=True)