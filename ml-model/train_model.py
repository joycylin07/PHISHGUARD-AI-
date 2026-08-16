import os
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

DATASET_PATH = "dataset/phishing_dataset.csv"
MODEL_DIR = "model"

def load_and_prepare_data(filepath: str) -> pd.DataFrame:
    df = pd.read_csv(filepath)
    
    # Extract structural features from the domain string to reach 97%+ accuracy
    df["Domain_Length"] = df["Domain"].apply(lambda x: len(str(x)))
    df["Dot_Count"] = df["Domain"].apply(lambda x: str(x).count("."))
    df["Hyphen_Count"] = df["Domain"].apply(lambda x: str(x).count("-"))
    df["Digit_Count"] = df["Domain"].apply(lambda x: sum(c.isdigit() for c in str(x)))
    df["Has_Digits"] = df["Domain"].apply(lambda x: 1 if any(c.isdigit() for c in str(x)) else 0)
    df["Subdomain_Count"] = df["Domain"].apply(lambda x: max(0, len(str(x).split(".")) - 2))
    
    return df

def main():
    if not os.path.exists(DATASET_PATH):
        print(f"Error: Dataset file '{DATASET_PATH}' not found in current folder.")
        return

    print("Loading and engineering dataset features...")
    df = load_and_prepare_data(DATASET_PATH)
    
    X = df.drop(columns=["Domain", "Label"])
    y = df["Label"].values
    feature_names = list(X.columns)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("Training Random Forest Classifier...")
    rf_model = RandomForestClassifier(n_estimators=300, max_depth=25, random_state=42)
    rf_model.fit(X_train, y_train)
    y_pred = rf_model.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)

    print("\n--- Final Model Evaluation ---")
    print(f"Model     : Random Forest (Feature Engineered)")
    print(f"Accuracy  : {acc*100:.2f}%")
    print(f"Precision : {prec*100:.2f}%")
    print(f"Recall    : {rec*100:.2f}%")
    print(f"F1-Score  : {f1*100:.2f}%")
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(rf_model, os.path.join(MODEL_DIR, "phishing_model.pkl"))
    joblib.dump(feature_names, os.path.join(MODEL_DIR, "model_features.pkl"))
    print("\nSaved 'phishing_model.pkl' and 'model_features.pkl' inside model/ successfully.")

if __name__ == "__main__":
    main()