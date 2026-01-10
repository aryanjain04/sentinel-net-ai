import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

def generate_training_data():
    """Creates a small synthetic dataset for the baseline model."""
    data = []
    
    for _ in range(200):
        data.append([np.random.uniform(1.0, 30.0), np.random.randint(5, 50), np.random.randint(500, 5000), 443, np.random.randint(49152, 65535), 0])
        data.append([np.random.uniform(0.1, 2.0), np.random.randint(2, 10), np.random.randint(60, 500), 53, np.random.randint(49152, 65535), 0])
        
        data.append([np.random.uniform(0.0, 0.05), np.random.randint(1, 3), np.random.randint(0, 120), np.random.randint(1, 1024), 4444, 1])
        data.append([np.random.uniform(0.01, 0.8), np.random.randint(200, 2000), np.random.randint(20000, 200000), 80, np.random.randint(1, 65535), 1])

    return pd.DataFrame(
        data,
        columns=["duration", "packet_count", "byte_count", "server_port", "client_port", "label"],
    )

def train_baseline(output_path: str = "baseline_rf.joblib"):
    print("--- SentinelNet-AI: Training ML Baseline ---")
    df = generate_training_data()
    
    X = df.drop('label', axis=1)
    y = df['label']

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X, y)

    joblib.dump(model, output_path)
    print(f"Model exported to {output_path}")

if __name__ == "__main__":
    train_baseline()