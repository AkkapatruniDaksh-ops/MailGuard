🛡️ MailGuard — Email Spam & Phishing Detection System

MailGuard is a Python-based cybersecurity project that analyzes email content to identify suspicious patterns and classify potentially unwanted messages using machine learning and rule-based detection.

It provides an interactive Streamlit dashboard for email analysis, making it easier to inspect suspicious messages and understand potential email threats.

🚀 Key Features

Machine Learning Detection: Classifies emails using a trained spam detection model.
Rule-Based Analysis: Identifies suspicious phrases and patterns in email content.
Subject & Body Analysis: Examines both the subject and message body.
Email File Parsing: Supports plain-text ".eml" email files.
URL Extraction: Extracts links from emails and provides basic warning indicators.
Interactive Dashboard: Provides a user-friendly Streamlit interface.
Session History: Keeps track of analyses during the session.
CSV Export: Allows analysis history to be exported for further review.
🧰 Technologies Used

Technology| Purpose Python| Core programming language Streamlit| Interactive web dashboard Scikit-learn| Machine learning classification Pandas| Data processing joblib| Saving and loading the trained model

📁 Project Structure

MailGuard/ │ ├── app.py ├── detector.py ├── train_model.py ├── requirements.txt │ ├── data/ │ └── emails.csv │ ├── model/ │ └── saved model files │ └── reports/

⚙️ Installation & Setup

Clone the repository
git clone https://github.com/AkkapatruniDaksh-ops/MailGuard.git cd MailGuard

Create a virtual environment
python -m venv .venv

Activate the environment
Windows PowerShell:

..venv\Scripts\Activate.ps1

Install dependencies
python -m pip install -r requirements.txt

Prepare the dataset
Ensure "data/emails.csv" contains the required "text" and "label" columns.

Train the model
python train_model.py

Run MailGuard
python -m streamlit run app.py

The application will open in your browser.

🔍 How It Works

The user provides email text or uploads a supported ".eml" file.
MailGuard extracts the email content.
Rule-based checks inspect suspicious phrases and patterns.
The machine learning model classifies the email.
Extracted URLs and warning indicators are presented.
The analysis can be reviewed in session history and exported as CSV.
🎯 Project Objective

The objective of MailGuard is to demonstrate how machine learning and rule-based techniques can be combined to support email security analysis and phishing awareness.

⚠️ Limitations

MailGuard is an educational cybersecurity prototype.
Spam classification does not guarantee phishing detection.
Rule-based checks are heuristic and may produce false positives or false negatives.
Detection performance depends on the quality and size of the training dataset.
A suspicious or safe classification should not be treated as definitive proof.
👨‍💻 Author

Daksh Akkapatruni

GitHub: "AkkapatruniDaksh-ops" (https://github.com/AkkapatruniDaksh-ops)

⭐ If you find this project interesting, consider starring the repository!

## 📸 Application Screenshots

### Main Dashboard
![MailGuard Dashboard](screenshots/dashboard.png)

### Email Detection Result
![Detection Result](screenshots/detection-result.png)

### Email Analysis
![Email Analysis](screenshots/email-analysis.png)
