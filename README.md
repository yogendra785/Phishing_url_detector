# 🛡️ Phishing URL Detection using Machine Learning

Detect whether a URL is **phishing** or **legitimate** using a trained machine learning model powered by `RandomForestClassifier`. This project includes both a backend model and a frontend built with **Streamlit**.

---

## 🚀 Project Highlights

- 🔍 **Accuracy**: Achieved **98.95%** accuracy on balanced dataset
- 🧠 **Model Used**: Random Forest Classifier (Sklearn)
- 🔍 **Features Extracted from URL**: URL length, domain patterns, special characters, HTTPS, trusted domain check, and more
- ✅ **Trusted Domain Whitelisting** to avoid false positives like `google.com` and `instagram.com`
- 🖥️ **Streamlit Web App** with:
  - Single URL Prediction
  - Batch CSV Upload + Download Results
- 📊 **Confusion Matrix**, Precision, Recall, and F1 Score calculated

---

## 🧠 Tools & Libraries

- `Python`
- `Pandas`, `Scikit-learn`, `TLDExtract`, `Joblib`, `Streamlit`
- Model persistence using `.pkl`

---

## 📁 Features Extracted

| Feature | Description |
|---------|-------------|
| `url_length` | Total characters in the URL |
| `num_dots` | Number of `.` in the URL |
| `has_ip` | Whether URL contains IP address |
| `has_at`, `has_dash` | Suspicious symbols |
| `is_https` | Is connection secure? |
| `suspicious_keywords_count` | Count of terms like `login`, `verify`, etc. |
| `is_trusted_domain` | Whitelisted trusted domains |
| … and more |

---



---

## 🧪 Try It Yourself

```bash
git clone https://github.com/yogendra785/phishing-url-detector.git
cd phishing-url-detector
pip install -r requirements.txt
streamlit run app.py
