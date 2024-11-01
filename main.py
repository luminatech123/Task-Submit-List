import streamlit as st
from PyPDF2 import PdfReader

# Title of the app
st.title("Cyber Security Internship Report Evaluation")

# File upload section
uploaded_file = st.file_uploader("Upload your report (PDF or Text)", type=["pdf", "txt"])

# Define keywords for each task in the internship
keywords = [
    # Task 1: Kali Linux - Hands-on Practice
    "Kali Linux", "Linux commands", "install tools", "GitHub", "Kali Linux tools",
    "perform attack", "basic commands", "advanced commands", "http://testphp.vulnweb.com",

    # Task 2: Information Gathering
    "Information Gathering", "Maltego", "Nmap", "target site", "network scanning",

    # Task 3: Sniffing Attack using Wireshark
    "sniffing attack", "Wireshark", "capture traffic", "analyze traffic", "sensitive information",
    "network vulnerability", "intercept data", "potential vulnerabilities",

    # Task 4: Password Cracking
    "password cracking", "John the Ripper", "Hashcat", "simple password", "crack password",
    "password123", "hash function", "brute force attack",

    # Task 5: Email Analysis
    "email analysis", "phishing email", "suspicious elements", "red flags", "avoid phishing",
    "email security", "analyze email", "threat identification"
]

# Function to read and process PDF content
def read_pdf(file):
    pdf_reader = PdfReader(file)
    text = ""
    for page in pdf_reader.pages:
        text += page.extract_text()
    return text

# Evaluate report function
def evaluate_report(content):
    score = 0
    feedback = []

    for keyword in keywords:
        if keyword.lower() in content.lower():
            score += 1
            feedback.append(f"Keyword '{keyword}' found in the report.")
        else:
            feedback.append(f"Keyword '{keyword}' not found.")

    return score, feedback

# Processing the uploaded file
if uploaded_file:
    if uploaded_file.type == "application/pdf":
        report_content = read_pdf(uploaded_file)
    elif uploaded_file.type == "text/plain":
        report_content = uploaded_file.read().decode("utf-8")
    else:
        st.error("Unsupported file type.")
        report_content = ""

    # Display report content
    st.subheader("Report Content")
    st.write(report_content)

    # Evaluate the report content
    score, feedback = evaluate_report(report_content)

    # Display score and feedback
    st.subheader("Evaluation Result")
    st.write(f"Score: {score}/{len(keywords)}")
    for comment in feedback:
        st.write(comment)

    # Display result based on score
    if score >= len(keywords) * 0.6:  # Pass if 60% of keywords are found
        st.success("Congratulations! You passed the evaluation.")
        
        # Link to certificate page
        st.markdown("[Click here to view your certificate](certificate1.html)", unsafe_allow_html=True)
    else:
        st.warning("You did not pass. Try improving the report content.")
