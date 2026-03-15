import pandas as pd
import numpy as np
import time
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import accuracy_score, f1_score
from app.services.url_features import URLFeatureExtractor

def prepare_url_data():
    print("Loading Dataset to extract URL features...")
    # Using the massive 2026 dataset we just generated
    df = pd.read_csv("data/dataset_2026_content.csv")
    
    # We only need the URL and the label for Model B
    df = df[['url', 'label']].dropna().drop_duplicates()
    
    # Since extracting features for 55k URLs might take a minute, let's do it and show progress
    print(f"Extracting URL features for {len(df)} rows...")
    features_list = []
    
    for url in df['url']:
        features_list.append(URLFeatureExtractor.extract_features(url))
        
    X = np.array(features_list)
    y = df['label'].values
    
    return X, y

def compare_models():
    X, y = prepare_url_data()
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    models = {
        "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42),
        "Decision Tree": DecisionTreeClassifier(random_state=42),
        "Gradient Boosting": GradientBoostingClassifier(random_state=42),
        "Logistic Regression": LogisticRegression(max_iter=1000, random_state=42),
        "K-Nearest Neighbors": KNeighborsClassifier(),
        "Naive Bayes": GaussianNB()
    }
    
    print("\n--- Model B (URL Analysis) Comparison ---")
    print(f"{'Model Name':<22} | {'Accuracy':<10} | {'F1-Score':<10} | {'Training Time':<15}")
    print("-" * 65)
    
    results = []
    for name, model in models.items():
        start_time = time.time()
        model.fit(X_train, y_train)
        train_time = time.time() - start_time
        
        preds = model.predict(X_test)
        acc = accuracy_score(y_test, preds)
        f1 = f1_score(y_test, preds)
        
        results.append((name, acc, f1, train_time))
        print(f"{name:<22} | {acc:.4f}     | {f1:.4f}     | {train_time:.2f}s")

if __name__ == "__main__":
    compare_models()
