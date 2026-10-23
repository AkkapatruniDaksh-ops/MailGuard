import csv
import io
from datetime import datetime

import streamlit as st

from detector import (
    inspect_email,
    predict_spam,
    read_eml_file,
)

st.set_page_config(
    page_title="MailGuard | Email Security",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ MailGuard")
st.subheader("Email Spam & Phishing Detection")
st.caption(
    "Analyze email content for spam patterns and potential "
    "phishing indicators. This is a student security prototype."
)

# Store analysis history for the current browser session
if "history" not in st.session_state:
    st.session_state.history = []

with st.sidebar:
    st.header("About MailGuard")
    st.write(
        "Analyze email text locally using rule-based indicators "
        "and an optional trained spam classifier."
    )
    st.warning(
        "This tool cannot guarantee an email is safe. "
        "Do not open suspicious links or attachments."
    )

    if st.button("Clear session history"):
        st.session_state.history = []

st.header("Analyze an email")

uploaded_file = st.file_uploader(
    "Optionally upload a plain-text .eml email",
    type=["eml"],
)

subject = ""
sender = ""
body = ""

if uploaded_file is not None:
    try:
        subject, sender, body = read_eml_file(
            uploaded_file.getvalue()
        )
        st.success("Email file parsed. Review its contents below.")
    except Exception as error:
        st.error(f"Could not parse email: {error}")

subject = st.text_input(
    "Email subject",
    value=subject,
)

sender = st.text_input(
    "Sender address (optional)",
    value=sender,
)

body = st.text_area(
    "Email message",
    value=body,
    height=220,
    placeholder="Paste the email's plain-text content here...",
)

if st.button("Analyze Email", type="primary"):
    if not subject.strip() and not body.strip():
        st.warning("Enter an email subject or message first.")
    else:
        rules = inspect_email(subject, body, sender)
        ml_result = predict_spam(subject, body)

        st.session_state.history.insert(
            0,
            {
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "subject": subject,
                "rule_label": rules["rule_label"],
                "ml_label": (
                    ml_result["label"] if ml_result else "Model not trained"
                ),
                "indicators": rules["indicators"],
            },
        )

        st.divider()
        st.header("Analysis results")

        left, right = st.columns(2)

        with left:
            st.metric(
                "Rule-based assessment",
                rules["rule_label"],
            )
            st.write(
                f"Rule points: {rules['risk_points']}"
            )

        with right:
            if ml_result:
                st.metric(
                    "ML spam classification",
                    ml_result["label"],
                )

                if ml_result["confidence"] is not None:
                    st.write(
                        "Model confidence: "
                        f"{ml_result['confidence']:.1%}"
                    )
            else:
                st.info(
                    "No trained model found. Run "
                    "`python train_model.py` first."
                )

        st.subheader("Detection indicators")

        if rules["indicators"]:
            for indicator in rules["indicators"]:
                st.write(f"⚠️ {indicator}")
        else:
            st.write("No configured rule indicators found.")

        if rules["urls"]:
            st.subheader("Extracted URLs")
            for url in rules["urls"]:
                # Display as text; do not visit the URL.
                st.code(url)

        st.caption(
            "Rule-based assessment and ML spam classification "
            "are separate signals. Neither proves an email is "
            "malicious or safe."
        )

st.divider()
st.header("Session analysis history")

history = st.session_state.history

if history:
    st.dataframe(
        [
            {
                "Time": item["time"],
                "Subject": item["subject"],
                "Rule assessment": item["rule_label"],
                "ML result": item["ml_label"],
            }
            for item in history
        ],
        use_container_width=True,
    )

    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "time",
            "subject",
            "rule_label",
            "ml_label",
            "indicators",
        ],
    )

    writer.writeheader()

    for item in history:
        writer.writerow({
            **item,
            "indicators": "; ".join(item["indicators"]),
        })

    st.download_button(
        "Download analysis history (CSV)",
        data=output.getvalue(),
        file_name="mailguard_history.csv",
        mime="text/csv",
    )
else:
    st.info("Your analyzed emails will appear here.")