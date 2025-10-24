from sklearn.ensemble import IsolationForest
import numpy as np

model = IsolationForest(n_estimators=50, contamination=0.05)
history = []

def learn(data_point):
    history.append(data_point)
    if len(history) > 50:
        X = np.array([[d["cpu"], d["ram"]] for d in history])
        model.fit(X)

def detect_anomaly(point):
    X = np.array([[point["cpu"], point["ram"]]])
    return int(model.predict(X)[0]) == -1
