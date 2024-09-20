from flask import Flask, request, render_template, redirect, url_for
import pickle

app = Flask(__name__)

if __name__=="__main__":
    @app.route("/")
    def Show_URL():
        return render_template("index.html")

    @app.route("/home")
    def home():
        return render_template("index.html")

    @app.route("/upload", methods = ["GET", "POST"])
    def upload():
        if request.method == "POST":
            url = request.form.get('url')
            return redirect(url_for('predict', url = url))
        return render_template("upload.html")

    @app.route("/predict")
    def predict():
        URL = request.args.get('url')
        model = pickle.load(open('model_with_feature_extraction.pkl', 'rb'))
        loaded_model = model['model']
        loaded_feature_extraction = model['feature_extraction_function']
        input = loaded_feature_extraction(URL)
        result = loaded_model.predict([input])
        return render_template("prediction1.html", result = result, url = URL)
    
    @app.route("/contact")
    def contact():
        return render_template("contact.html")
    
    @app.route("/about")
    def about():
        return render_template("about.html")

    @app.route("/login")
    def SignIn():
        return render_template("login.html")
    
    app.run(debug=False)
