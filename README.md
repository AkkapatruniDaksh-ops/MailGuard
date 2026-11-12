# MailGuard — Email Spam & Phishing Detection

## Project Overview

MailGuard is a Python-based cybersecurity project that analyzes email content for suspicious patterns and classifies messages using a machine-learning spam detector.

## Features

- Rule-based suspicious phrase detection
- Machine-learning spam classification
- Email subject and body analysis
- Plain-text email file (.eml) parsing
- URL extraction and basic warning indicators
- Streamlit web dashboard
- Session history and CSV export

## Technologies

- Python
- Streamlit
- Scikit-learn
- Pandas
- joblib

## Project Structure

- app.py — Web dashboard
- detector.py — Email analysis functions
- train_model.py — Model training and evaluation
- data/emails.csv — Labeled training data
- model/ — Saved trained classifier
- reports/ — Intended location for generated reports
- requirements.txt — Python dependencies

## Setup

1. Create a Python virtual environment.
2. Install the dependencies using:

   python -m pip install -r requirements.txt

3. Prepare data/emails.csv with text and label columns.
4. Train the classifier:

   python train_model.py

5. Launch the dashboard:

   python -m streamlit run app.py

## Limitations

This is an educational prototype. Spam classification does not guarantee phishing detection. The current rule checks are heuristic and cannot prove that an email is malicious or safe. Model performance depends on the quality and size of its training dataset.