from pathlib import Path

import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
)

BASE_DIR = Path(__file__).resolve().parent
DATA_PATH = BASE_DIR / "data" / "emails.csv"
MODEL_DIR = BASE_DIR / "model"
MODEL_PATH = MODEL_DIR / "spam_classifier.joblib"


def normalize_label(value):
    label = str(value).lower().strip()
    aliases = {
        "spam": "spam",
        "ham": "legitimate",
        "legitimate": "legitimate",
        "not_spam": "legitimate",
        "non_spam": "legitimate",
        "safe": "legitimate",
        "good": "legitimate",
        "notspam": "legitimate",
    }
    return aliases.get(label, label)


def main():
    if not DATA_PATH.exists():
        raise FileNotFoundError(f"Dataset not found at {DATA_PATH}.")

    data = pd.read_csv(DATA_PATH)

    # Validate the expected dataset columns
    required = {"text", "label"}
    if not required.issubset(data.columns):
        raise ValueError("CSV must contain text and label columns.")

    data = data.dropna(subset=["text", "label"]).copy()
    data["text"] = data["text"].astype(str).str.strip()
    data["label"] = data["label"].map(normalize_label)
    data = data[data["text"].ne("")]

    allowed_labels = {"spam", "legitimate"}
    if not set(data["label"]).issubset(allowed_labels):
        raise ValueError("Labels must be spam or legitimate (ham is also accepted).")

    if data.empty:
        raise ValueError("Dataset is empty after cleaning.")

    if data["label"].nunique() < 2:
        raise ValueError("Dataset must contain both classes.")

    class_counts = data["label"].value_counts()
    if (class_counts < 2).any():
        raise ValueError("Each class must contain at least 2 samples for a stratified train/test split.")

    # Split before fitting preprocessing/model steps
    X_train, X_test, y_train, y_test = train_test_split(
        data["text"],
        data["label"],
        test_size=0.25,
        random_state=42,
        stratify=data["label"],
    )

    model = Pipeline([
        (
            "tfidf",
            TfidfVectorizer(
                lowercase=True,
                stop_words="english",
                ngram_range=(1, 2),
            ),
        ),
        (
            "classifier",
            LogisticRegression(max_iter=1000),
        ),
    ])

    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    print("\n--- Model Evaluation ---")
    print(classification_report(
        y_test,
        predictions,
        zero_division=0,
    ))

    print("Confusion matrix:")
    print(confusion_matrix(
        y_test,
        predictions,
        labels=["legitimate", "spam"],
    ))

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)

    print(f"\nSaved model to: {MODEL_PATH}")


if __name__ == "__main__":
    main()