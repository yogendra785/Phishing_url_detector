import streamlit as st
import pandas as pd
import joblib
import re
import tldextract
from urllib.parse import urlparse

# Load the trained model
model = joblib.load("D:\major\phishing_detector_model.pkl")

# Whitelisted trusted domains
TRUSTED_DOMAINS = [
    'google.com', 'facebook.com', 'youtube.com', 'microsoft.com',
    'amazon.com', 'apple.com', 'linkedin.com', 'github.com',
    'wikipedia.org', 'instagram.com', 'twitter.com', 'nptel.ac.in'
]

SHORTENERS = ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly']
SUSPICIOUS_KEYWORDS = ['login', 'secure', 'account', 'update', 'bank', 'verify']

# Feature extraction (must match training)
def extract_safe_features(url):
    features = {}
    url = str(url).strip()

    features['url_length'] = len(url)
    features['num_dots'] = url.count('.')
    features['has_ip'] = int(bool(re.search(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', url)))
    features['has_at'] = int('@' in url)
    features['has_dash'] = int('-' in url)

    parsed = urlparse(url)
    features['path_length'] = len(parsed.path)
    features['num_query_params'] = len(parsed.query.split('&')) if parsed.query else 0
    features['is_https'] = int(parsed.scheme == 'https')

    ext = tldextract.extract(url)
    domain = ext.domain
    suffix = ext.suffix
    registered_domain = f"{domain}.{suffix}"

    features['domain_length'] = len(domain)
    features['tld_length'] = len(suffix)
    features['is_shortened'] = int(any(short in url for short in SHORTENERS))
    features['suspicious_keywords_count'] = sum(keyword in url.lower() for keyword in SUSPICIOUS_KEYWORDS)
    features['is_trusted_domain'] = int(registered_domain in TRUSTED_DOMAINS)

    return features

# Streamlit UI
st.set_page_config(page_title="Phishing URL Detector", layout="centered")
st.title("🛡️ Phishing URL Detection App")

st.markdown("""
Detect whether a URL is **phishing** or **legitimate** using a trained machine learning model (RandomForestClassifier).  
You can test a single URL or upload a CSV file with multiple URLs.
""")

tab1, tab2 = st.tabs(["🔍 Single URL Test", "📁 Batch CSV Upload"])

# --- Single URL Prediction ---
with tab1:
    st.subheader("🔗 Enter a URL:")
    input_url = st.text_input("Example: https://secure-login.amazon-support.ru")

    if st.button("🔮 Predict"):
        if input_url:
            features = extract_safe_features(input_url)
            domain = tldextract.extract(input_url).registered_domain

            if domain in TRUSTED_DOMAINS:
                st.success("✅ Legitimate (Whitelisted Domain)")
            else:
                X_test = pd.DataFrame([features])
                prediction = model.predict(X_test)[0]
                prob = model.predict_proba(X_test)[0]

                label = "🟥 Phishing" if prediction == 1 else "🟩 Legitimate"
                confidence = round(max(prob) * 100, 2)

                if prediction == 1:
                    st.error(f"{label} (Confidence: {confidence}%)")
                else:
                    st.success(f"{label} (Confidence: {confidence}%)")
        else:
            st.warning("Please enter a valid URL.")

# --- Batch CSV Upload ---
with tab2:
    st.subheader("📤 Upload CSV file with a 'url' column:")
    uploaded_file = st.file_uploader("Choose a CSV file", type=["csv"])

    if uploaded_file:
        try:
            df = pd.read_csv(uploaded_file)

            if 'url' not in df.columns:
                st.error("CSV must have a column named 'url'.")
            else:
                df['features'] = df['url'].apply(extract_safe_features)
                features_df = pd.DataFrame(df['features'].tolist())

                # Predict
                predictions = model.predict(features_df)
                probs = model.predict_proba(features_df)

                result_df = df.copy()
                result_df['Prediction'] = predictions
                result_df['Confidence (%)'] = [round(max(p) * 100, 2) for p in probs]
                result_df['Label'] = result_df['Prediction'].apply(lambda x: "Phishing" if x == 1 else "Legitimate")

                st.dataframe(result_df[['url', 'Label', 'Confidence (%)']], use_container_width=True)

                csv = result_df.to_csv(index=False).encode('utf-8')
                st.download_button("⬇️ Download Results", data=csv, file_name="phishing_predictions.csv", mime="text/csv")
        except Exception as e:
            st.error(f"Something went wrong: {e}")
