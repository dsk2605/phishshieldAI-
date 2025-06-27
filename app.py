from flask import Flask, request, jsonify
import pandas as pd
import re
import joblib

app = Flask(__name__)

model = joblib.load("model.pkl")

data_url = "https://raw.githubusercontent.com/GregaVrbancic/Phishing-Dataset/master/dataset_small.csv"
data = pd.read_csv(data_url)

def extract_features(url):
    if not url.startswith("http"):
        url = "http://" + url

    parts = url.split('/')
    domain = parts[2] if len(parts) > 2 else ""

    features = {
        'qty_dot_url': url.count('.'),
        'qty_hyphen_url': url.count('-'),
        'qty_underline_url': url.count('_'),
        'qty_slash_url': url.count('/'),
        'qty_questionmark_url': url.count('?'),
        'qty_equal_url': url.count('='),
        'qty_at_url': url.count('@'),
        'qty_and_url': url.count('&'),
        'qty_exclamation_url': url.count('!'),
        'qty_space_url': url.count(' '),
        'qty_tilde_url': url.count('~'),
        'qty_comma_url': url.count(','),
        'qty_plus_url': url.count('+'),
        'qty_asterisk_url': url.count('*'),
        'qty_hashtag_url': url.count('#'),
        'qty_dollar_url': url.count('$'),
        'qty_percent_url': url.count('%'),
        'qty_tld_url': len(re.findall(r'\.[a-z]{2,6}', url)),
        'length_url': len(url),
        'qty_dot_domain': domain.count('.'),
        'qty_hyphen_domain': domain.count('-'),
        'qty_underline_domain': domain.count('_'),
        'qty_slash_domain': domain.count('/'),
        'qty_questionmark_domain': domain.count('?'),
        'qty_equal_domain': domain.count('='),
        'qty_at_domain': domain.count('@'),
        'qty_and_domain': domain.count('&'),
        'qty_exclamation_domain': domain.count('!'),
        'qty_space_domain': domain.count(' '),
        'qty_tilde_domain': domain.count('~'),
        'qty_comma_domain': domain.count(','),
        'qty_plus_domain': domain.count('+'),
        'qty_asterisk_domain': domain.count('*'),
        'qty_hashtag_domain': domain.count('#'),
        'qty_dollar_domain': domain.count('$'),
        'qty_percent_domain': domain.count('%'),
        'domain_length': len(domain),
        'domain_in_ip': 1 if re.search(r'\d+\.\d+\.\d+\.\d+', domain) else 0,
        'server_client_domain': 1 if 'www' in domain else 0,
    }

    return features

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        url = data.get("url")

        if not url:
            return jsonify({"error": "No URL provided"}), 400

        features = extract_features(url)
        df = pd.DataFrame([features])

        
        if list(df.columns) == list(model.feature_names_in_):
            prediction = model.predict(df)[0]
            return jsonify({
                "phishing": bool(prediction),
                "message": "Phishing detected!" if prediction == 1 else "This link is safe."
            })
        else:
            return jsonify({"error": "Feature mismatch with model!"}), 500

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
