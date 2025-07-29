import joblib
import os

model_path = os.path.join(os.path.dirname(__file__), '..', 'rf_model.pkl')
model = joblib.load(model_path)

def classify_threat(vt_data, shodan_data):
    try:
        features = [
            vt_data.get("positives", 0),
            vt_data.get("suspicious", 0),
            len(shodan_data.get("ports", [])),
            len(shodan_data.get("vulns", []))
        ]
        prediction = model.predict([features])[0]
        return "Malicious" if prediction == 1 else "Benign"
    except:
        return "Unknown"
