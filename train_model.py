from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib
import numpy as np

# Dummy dataset: [positives, suspicious, open_ports, vulns]
X = np.array([
    [20, 5, 3, 2],
    [0, 0, 1, 0],
    [15, 3, 5, 5],
    [1, 0, 2, 0],
    [25, 10, 6, 8]
])
y = [1, 0, 1, 0, 1]  # 1 = Malicious, 0 = Benign

model = RandomForestClassifier()
model.fit(X, y)

joblib.dump(model, "rf_model.pkl")
