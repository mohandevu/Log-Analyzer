import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import re
import json
import os
import smtplib
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import numpy as np
from collections import defaultdict, deque
from Evtx.Evtx import Evtx  # For reading .evtx files
from xml.etree import ElementTree as ET  # For parsing .evtx content
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from sklearn.cluster import KMeans
import dash
from dash import dcc, html
from dash.dependencies import Input, Output
import plotly.express as px
import pandas as pd

# Dash Application for Visualization
app = dash.Dash(__name__, external_stylesheets=['https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css'])

# Sample DataFrame for Dashboard Visualization (You can load real log data here)
df = pd.DataFrame({
    "Event Type": ["Failed Login", "Unauthorized Access", "Privilege Escalation", "Malicious Execution"],
    "Count": [50, 20, 5, 2],
    "Severity": ["Medium", "High", "Critical", "Critical"]
})

# Layout of the dashboard
app.layout = html.Div([
    html.H1("Log Analysis Dashboard", style={'text-align': 'center'}),
    
    dcc.Dropdown(id="select_severity",
                 options=[
                     {"label": "All", "value": "All"},
                     {"label": "Medium", "value": "Medium"},
                     {"label": "High", "value": "High"},
                     {"label": "Critical", "value": "Critical"}],
                 multi=False,
                 value="All",
                 style={"width": "40%"},
                 placeholder="Select Severity"),
    
    dcc.Graph(id='event_bar_chart', figure={}),
    html.Div(id='total_logs_processed', children=[])
])

# Callback to update the chart based on severity selection
@app.callback(
    [Output(component_id='event_bar_chart', component_property='figure'),
     Output(component_id='total_logs_processed', component_property='children')],
    [Input(component_id='select_severity', component_property='value')]
)
def update_graph(selected_severity):
    if selected_severity == "All":
        filtered_df = df
    else:
        filtered_df = df[df["Severity"] == selected_severity]

    # Create bar chart
    fig = px.bar(filtered_df, x="Event Type", y="Count", color="Severity",
                 title="Event Count by Type and Severity", barmode='group')

    # Update the total logs processed
    total_logs = df["Count"].sum()
    return fig, f"Total Logs Processed: {total_logs}"

# Run the Dash app
def run_dashboard():
    app.run_server(debug=True, use_reloader=False)

# Admin email configuration
admin_email = "mohandevu@gmail.com"  # Set this as the admin email address


# IP blocking threshold (block after X failed login attempts)
BLOCK_THRESHOLD = 5

# Predefined patterns with base severity levels
patterns = {
    'Failed Login': (re.compile(r'failed login|authentication failure', re.IGNORECASE), 'Medium', 50),
    'Unauthorized Access': (re.compile(r'unauthorized access|access denied|permission denied', re.IGNORECASE), 'High', 100),
    'Privilege Escalation': (re.compile(r'privilege escalation|root access|admin rights granted', re.IGNORECASE), 'Critical', 200),
    'Malicious Execution': (re.compile(r'malicious|script executed|suspicious command', re.IGNORECASE), 'Critical', 300),
    'File Tampering': (re.compile(r'file modified|file tampered|unexpected change', re.IGNORECASE), 'High', 100),
}

# Remedies for each suspicious activity
remedies = {
    'Failed Login': "Review the failed login attempts and investigate for possible brute-force attacks.",
    'Unauthorized Access': "Check system logs for unauthorized access attempts and change access policies if necessary.",
    'Privilege Escalation': "Investigate the source of privilege escalation and verify if it was intentional.",
    'Malicious Execution': "Inspect the executed scripts or commands for malicious behavior and isolate if needed.",
    'File Tampering': "Verify the integrity of the modified files and restore them if unexpected changes are found."
}

# ML Models
isolation_forest = IsolationForest(contamination=0.1, random_state=42)
kmeans = KMeans(n_clusters=3, random_state=42)

# Track events for correlation
event_window = deque(maxlen=100)  # Store the last 100 events for correlation
time_window = deque(maxlen=100)  # Store timestamps of events for correlation

# Dynamic severity ranking system
severity_thresholds = {
    'Low': 30,
    'Medium': 80,
    'High': 150,
    'Critical': 250
}

# Real-time risk score
risk_score = 0

# Track user logins and actions for correlation
user_actions = defaultdict(list)  # Store events by user

# Track event timestamps for time correlation
event_timestamps = defaultdict(list)

# Sliding time window for correlation
TIME_WINDOW = timedelta(minutes=5)  # Set a 5-minute sliding window for event correlation

# Create a threading event to signal when to stop monitoring
stop_event = threading.Event()

# Define compliance rules for GDPR, PCI-DSS, and HIPAA
compliance_rules = {
    'GDPR': {
        'PII Exposed': re.compile(r'(name|email|address|phone|credit card|social security)', re.IGNORECASE),
        'Access Control': re.compile(r'(unauthorized access|access denied|permission denied)', re.IGNORECASE)
    },
    'PCI-DSS': {
        'Credit Card Data': re.compile(r'\b(?:\d[ -]*?){13,16}\b', re.IGNORECASE),  # Detects credit card numbers
        'Security Breach': re.compile(r'(security breach|hack|compromise)', re.IGNORECASE)
    },
    'HIPAA': {
        'PHI Exposed': re.compile(r'(medical record|patient data|health info|diagnosis)', re.IGNORECASE),
        'Access Control': re.compile(r'(unauthorized access|access denied|permission denied)', re.IGNORECASE)
    }
}

# Remedies for compliance violations
compliance_remedies = {
    'GDPR': "Review data handling policies and ensure personal data is anonymized or protected.",
    'PCI-DSS': "Ensure secure storage of credit card data and restrict access to sensitive information.",
    'HIPAA': "Ensure PHI (Protected Health Information) is handled in accordance with HIPAA standards and access is restricted."
}


# Function to block an IP address
def block_ip(ip_address):
    try:
        if platform.system() == "Linux":
            # Linux command to block the IP using iptables
            os.system(f"sudo iptables -A INPUT -s {ip_address} -j DROP")
        elif platform.system() == "Windows":
            # Windows command to block the IP using netsh
            os.system(f"netsh advfirewall firewall add rule name=\"Block {ip_address}\" dir=in action=block remoteip={ip_address}")
        update_status(f"IP {ip_address} has been blocked.")
    except Exception as e:
        update_status(f"Failed to block IP {ip_address}: {e}")

# Function to send an email alert to the admin
def send_alert(subject, message):
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_USER
        msg['To'] = admin_email
        msg['Subject'] = subject

        msg.attach(MIMEText(message, 'plain'))

        # Setup the server
        server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASS)
        
        # Send the email
        server.send_message(msg)
        server.quit()
        update_status("Alert email sent to the admin.")
    except Exception as e:
        update_status(f"Failed to send alert email: {e}")

# Function to detect IP addresses in log entries
def detect_ip_addresses(log_entry):
    ip_pattern = r'[0-9]+(?:\.[0-9]+){3}'  # Basic regex pattern for IPv4 addresses
    return re.findall(ip_pattern, log_entry)
def check_compliance(log_entry):
    """Check log entry for compliance violations."""
    compliance_violations = defaultdict(list)

    # Check GDPR compliance
    for rule_name, pattern in compliance_rules['GDPR'].items():
        if pattern.search(log_entry):
            compliance_violations['GDPR'].append(rule_name)

    # Check PCI-DSS compliance
    for rule_name, pattern in compliance_rules['PCI-DSS'].items():
        if pattern.search(log_entry):
            compliance_violations['PCI-DSS'].append(rule_name)

    # Check HIPAA compliance
    for rule_name, pattern in compliance_rules['HIPAA'].items():
        if pattern.search(log_entry):
            compliance_violations['HIPAA'].append(rule_name)

    return compliance_violations

def generate_compliance_report(compliance_results):
    """Generate a compliance audit report based on the compliance results."""
    report_file = "compliance_audit_report.txt"
    with open(report_file, 'w') as f:
        f.write("Compliance Audit Report\n")
        f.write("=" * 30 + "\n")

        if not compliance_results:
            f.write("No compliance violations found.\n")
        else:
            for standard, violations in compliance_results.items():
                f.write(f"{standard} Compliance Violations:\n")
                for violation in violations:
                    f.write(f"  - {violation}\n")
                    f.write(f"    Remedy: {compliance_remedies.get(standard, 'No remedy available')}\n")
                f.write("\n")

    print(f"Compliance audit report saved to: {report_file}")
    return report_file

def analyze_log_file(log_file):
    suspicious_activity = defaultdict(lambda: [0, [], ''])  # Store count, log lines, and severity
    total_lines = 0

    try:
        if log_file.endswith('.log') or log_file.endswith('.txt'):
            with open(log_file, 'r') as f:
                for line in f:
                    total_lines += 1
                    for activity, (pattern, severity) in patterns.items():
                        if pattern.search(line):
                            suspicious_activity[activity][0] += 1
                            suspicious_activity[activity][1].append(line.strip())  # Save matching log lines
                            suspicious_activity[activity][2] = severity

        elif log_file.endswith('.evtx'):
            with Evtx(log_file) as evtx:
                for record in evtx.records():
                    total_lines += 1
                    try:
                        xml_content = ET.fromstring(record.xml())
                        event_data = "".join(xml_content.itertext())  # Convert XML to plain text
                        for activity, (pattern, severity) in patterns.items():
                            if pattern.search(event_data):
                                suspicious_activity[activity][0] += 1
                                suspicious_activity[activity][1].append(event_data.strip())
                                suspicious_activity[activity][2] = severity
                    except ET.ParseError as parse_error:
                        print(f"XML parsing error in record: {parse_error}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to analyze file: {str(e)}")

    # Print what is being returned
    print(f"Returning: {suspicious_activity}, {total_lines}")
    
    # Ensure only two values are returned
    return suspicious_activity, total_lines

    try:
        # Extract event data from the log record
        xml_content = ET.fromstring(record.xml())
        event_data = "".join(xml_content.itertext())

        # Check for suspicious activity
        for event_name, (pattern, base_severity_level, base_severity_score) in patterns.items():
            if pattern.search(event_data):
                suspicious_activity[event_name][0] += 1
                suspicious_activity[event_name][1].append(event_data.strip())
                suspicious_activity[event_name][2] = base_severity_level

        # Check for compliance violations
        compliance_violations = check_compliance(event_data)
        if compliance_violations:
            for standard, violations in compliance_violations.items():
                compliance_results[standard].extend(violations)

    except ET.ParseError as e:
        print(f"Error parsing log record: {e}")

    return suspicious_activity, compliance_results

def run_analysis():
    # Allow selection of all file types as well as log, evtx, and txt files
    log_file = filedialog.askopenfilename(
        title="Select Log File", 
        filetypes=[
            ("Log Files", "*.log *.evtx *.txt"),  # Default option for log, evtx, and txt files
            ("All Files", "*.*")                  # Option to allow any file type
        ]
    )
    
    if not log_file:
        return

    # Check file extension to determine the type of file
    file_extension = os.path.splitext(log_file)[-1].lower()

    suspicious_activity = defaultdict(lambda: [0, [], ''])
    compliance_results = defaultdict(list)

    if file_extension == '.evtx':
        # Handle .evtx files using Evtx parser
        with Evtx(log_file) as evtx:
            for record in evtx.records():
                suspicious_act, compliance = analyze_event_log(record)
                for key, value in suspicious_act.items():
                    suspicious_activity[key][0] += value[0]
                    suspicious_activity[key][1].extend(value[1])
                    suspicious_activity[key][2] = value[2]

                for key, value in compliance.items():
                    compliance_results[key].extend(value)

    elif file_extension in ['.log', '.txt']:
        # Handle .log and .txt files as plain text files
        with open(log_file, 'r') as log:
            for line in log:
                suspicious_act, compliance = analyze_log_line(line)
                for key, value in suspicious_act.items():
                    suspicious_activity[key][0] += value[0]
                    suspicious_activity[key][1].extend(value[1])
                    suspicious_activity[key][2] = value[2]

                for key, value in compliance.items():
                    compliance_results[key].extend(value)

    # Save and display compliance report
    compliance_report_file = generate_compliance_report(compliance_results)
    messagebox.showinfo("Compliance Audit", f"Compliance audit completed. Report saved to {compliance_report_file}")

    # Display results in the GUI
    update_analysis_results(suspicious_activity, len(suspicious_activity))



def analyze_log_file(log_file):
    suspicious_activity = defaultdict(lambda: [0, [], ''])  # Store count, log lines, and severity
    total_lines = 0

    try:
        if log_file.endswith('.log'):
            with open(log_file, 'r') as f:
                for line in f:
                    total_lines += 1
                    for activity, (pattern, severity) in patterns.items():
                        if pattern.search(line):
                            suspicious_activity[activity][0] += 1
                            suspicious_activity[activity][1].append(line.strip())  # Save matching log lines
                            suspicious_activity[activity][2] = severity
        elif log_file.endswith('.evtx'):
            with Evtx(log_file) as evtx:
                for record in evtx.records():
                    total_lines += 1
                    try:
                        xml_content = ET.fromstring(record.xml())
                        event_data = "".join(xml_content.itertext())  # Convert XML to plain text
                        for activity, (pattern, severity) in patterns.items():
                            if pattern.search(event_data):
                                suspicious_activity[activity][0] += 1
                                suspicious_activity[activity][1].append(event_data.strip())
                                suspicious_activity[activity][2] = severity
                    except ET.ParseError as parse_error:
                        print(f"XML parsing error in record: {parse_error}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to analyze file: {str(e)}")

    return suspicious_activity, total_lines



# Function to correlate events and automate remediation
def correlate_events(event_name, log_entry, user=None):
    global risk_score
    event_window.append(event_name)
    time_window.append(datetime.now())

    # Example pattern: Series of Failed Logins followed by Privilege Escalation
    if event_name == 'Privilege Escalation' and user:
        failed_login_count = user_actions[user].count('Failed Login')
        if failed_login_count >= 3:
            risk_score += 200  # Raise risk score if this pattern is detected
            messagebox.showwarning("Correlation Detected", f"User {user} had multiple failed logins followed by privilege escalation! Possible attack pattern detected.")
            send_alert("Critical Alert: Privilege Escalation", f"Multiple failed logins followed by privilege escalation detected for user {user}.")

    # Automate IP blocking after multiple failed login attempts
    if event_name == 'Failed Login':
        ip_addresses = detect_ip_addresses(log_entry)
        for ip in ip_addresses:
            failed_attempts = user_actions[user].count('Failed Login')
            if failed_attempts >= BLOCK_THRESHOLD:
                block_ip(ip)  # Block the IP address after threshold is met
                send_alert("Blocked IP Address", f"The IP address {ip} has been blocked due to multiple failed login attempts.")
    
    # Adjust severity based on event timing
    adjust_severity_by_time(event_name, datetime.now())

# Adjust severity based on timing of events
def adjust_severity_by_time(event_name, event_time):
    global risk_score
    now = datetime.now()
    
    # Check if event occurred within the defined time window
    if event_timestamps[event_name] and (now - event_timestamps[event_name][-1]) < TIME_WINDOW:
        risk_score += 50  # Increase risk score for frequent, high-risk events
        messagebox.showwarning("Severity Increase", f"Event '{event_name}' occurred again within {TIME_WINDOW}. Risk score increased.")

    event_timestamps[event_name].append(now)

# Event log analysis
def analyze_event_log(record, user=None):
    suspicious_activity = defaultdict(lambda: [0, [], ''])
    try:
        xml_content = ET.fromstring(record.xml())
        event_data = "".join(xml_content.itertext())  # Convert XML to plain text
        for event_name, (pattern, base_severity_level, base_severity_score) in patterns.items():
            if pattern.search(event_data):
                suspicious_activity[event_name][0] += 1
                suspicious_activity[event_name][1].append(event_data.strip())
                suspicious_activity[event_name][2] = base_severity_level
                
                # Correlate this event with others in the window
                correlate_events(event_name, event_data, user)
                
    except ET.ParseError as parse_error:
        print(f"XML parsing error in record: {parse_error}")
    return suspicious_activity

# ML-based anomaly detection
def extract_features(log_lines):
    features = []
    for line in log_lines:
        features.append([len(line), sum(1 for c in line if c.isdigit()), sum(1 for c in line if c.isalpha())])
    return np.array(features)

def detect_anomalies(log_lines):
    features = extract_features(log_lines)
    anomalies = isolation_forest.fit_predict(features)
    return anomalies

def detect_kmeans_anomalies(log_lines):
    features = extract_features(log_lines)
    kmeans.fit(features)
    distances = kmeans.transform(features).min(axis=1)
    threshold = np.percentile(distances, 90)  # Set threshold for anomaly
    return distances > threshold

# Save the report after analysis
def save_report(log_file, suspicious_activity, total_lines):
    report_file = log_file.replace('.log', '_output.txt').replace('.evtx', '_output.txt').replace('.json', '_output.txt').replace('.syslog', '_output.txt')
    with open(report_file, 'w') as f:
        f.write(f'Total lines processed: {total_lines}\n\n')
        if suspicious_activity:
            for activity, (count, logs, severity) in suspicious_activity.items():
                f.write(f'{activity} (Severity: {severity}): {count}\n')
                f.write(f'{remedies.get(activity, "No remedy available")}\n\n')
                f.write(f"Example log lines:\n")
                for log in logs[:5]:  # Show up to 5 matching log lines
                    f.write(f"  - {log}\n")
                f.write("\n")
        else:
            f.write('No suspicious activity detected.\n')
    return report_file

# Dynamic severity calculation
def calculate_dynamic_severity(event_name, frequency, base_severity):
    severity_score = base_severity + (frequency * 10)
    
    if severity_score > severity_thresholds['Critical']:
        risk_category = 'Critical'
    elif severity_score > severity_thresholds['High']:
        risk_category = 'High'
    elif severity_score > severity_thresholds['Medium']:
        risk_category = 'Medium'
    else:
        risk_category = 'Low'
    
    return severity_score, risk_category

# Update GUI with analysis results
def update_analysis_results(suspicious_activity, total_lines):
    for widget in analysis_results_frame.winfo_children():
        widget.destroy()

    tk.Label(analysis_results_frame, text=f"Total lines processed: {total_lines}", font=("Helvetica", 12)).pack(pady=5)

    if suspicious_activity:
        for activity, (count, logs, severity) in suspicious_activity.items():
            tk.Label(analysis_results_frame, text=f'{activity} (Severity: {severity}): {count}', font=("Helvetica", 12)).pack(pady=2)
            tk.Label(analysis_results_frame, text=f'{remedies.get(activity, "No remedy available")}', font=("Helvetica", 10)).pack(pady=2)
            for log in logs[:5]:  # Display up to 5 log lines for each activity
                tk.Label(analysis_results_frame, text=f'Log: {log}', font=("Helvetica", 10)).pack(pady=1)
    else:
        tk.Label(analysis_results_frame, text='No suspicious activity detected.', font=("Helvetica", 12)).pack(pady=5)

# Display graph for suspicious activity
def plot_suspicious_activity(suspicious_activity):
    if not suspicious_activity:
        return None

    activities = list(suspicious_activity.keys())
    counts = [data[0] for data in suspicious_activity.values()]

    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(activities, counts, color='blue')
    ax.set_xlabel('Activity Type')
    ax.set_ylabel('Count')
    ax.set_title('Suspicious Activity Detected in Logs')

    return fig

# Run the analysis for the selected log file
def run_analysis():
    log_file = filedialog.askopenfilename(title="Select Log File", filetypes=[("Log Files", "*.evtx")])
    if not log_file:
        return

    suspicious_activity, total_lines, ml_anomalies, kmeans_anomalies = analyze_log_file(log_file)
    report_file = save_report(log_file, suspicious_activity, total_lines)
    
    result_message = f"Analysis complete!\nReport saved to: {report_file}\n"
    
    # Display ML-based anomaly detection results
    result_message += f"Isolation Forest Anomalies: {sum(ml_anomalies == -1)}\n"
    result_message += f"K-Means Anomalies: {sum(kmeans_anomalies)}\n"
    
    messagebox.showinfo("Analysis Complete", result_message)

    if suspicious_activity:
        alert_message = "Suspicious activity detected!"
        messagebox.showwarning("Alert", alert_message)
        
        # Plot the graph if suspicious activity is detected
        fig = plot_suspicious_activity(suspicious_activity)
        if fig:
            display_graph(fig)
    
    update_analysis_results(suspicious_activity, total_lines)

# Display matplotlib figure in the Tkinter GUI
def display_graph(fig):
    canvas = FigureCanvasTkAgg(fig, master=tab_analysis)
    canvas.draw()
    canvas.get_tk_widget().pack(pady=10, fill=tk.BOTH, expand=True)

# Real-time monitoring function
def real_time_monitor():
    global stop_event
    stop_event.clear()  # Clear any previous stop events

    try:
        log_dir = os.path.join(os.environ['SystemRoot'], 'System32', 'Winevt', 'Logs')  # Path to Windows Event Logs
        log_file = os.path.join(log_dir, 'Security.evtx')  # Example: Monitor Security Event Log (changeable)

        def monitor():
            total_lines = 0
            update_status("Monitoring started...")
            with Evtx(log_file) as evtx:
                for record in evtx.records():
                    if stop_event.is_set():  # Check if stop signal is set
                        update_status("Monitoring stopped.")
                        break  # Exit the loop immediately if stop signal is received
                        
                    total_lines += 1
                    suspicious_activity = analyze_event_log(record)
                    if suspicious_activity:
                        update_analysis_results(suspicious_activity, total_lines)  # Update result for real-time log line
                    update_status(f"Processed {total_lines} log entries")

                    # Check periodically if the stop signal has been triggered
                    if stop_event.is_set():
                        update_status("Monitoring stopped.")
                        break

                update_status("Monitoring stopped.")

        # Run monitoring in a separate thread
        threading.Thread(target=monitor, daemon=True).start()

    except Exception as e:
        messagebox.showerror("Error", f"Failed to monitor logs: {str(e)}")

# Start monitoring button action
def start_monitoring():
    global stop_event
    stop_event.clear()  # Reset the stop event before starting
    real_time_monitor()

# Stop monitoring button action
def stop_monitoring():
    global stop_event
    stop_event.set()  # Signal the monitoring thread to stop
    update_status("Stopping monitoring...")  # Notify the user that we're stopping

# Update the status label in the GUI
def update_status(message):
    status_label.config(text=message)

# Quit the application
def quit_application():
    root.quit()

# Create the GUI
def create_gui():
    global root, tab_analysis, analysis_results_frame, status_label

    root = tk.Tk()
    root.title("Log Analyzer")
    root.geometry("800x600")

    tab_control = ttk.Notebook(root)
    tab_analysis = ttk.Frame(tab_control)

    tab_control.add(tab_analysis, text='Log Analysis')
    tab_control.pack(expand=1, fill='both')

    # Tab: Log Analysis
    tk.Label(tab_analysis, text="Log Analyzer Tool", font=("Helvetica", 16)).pack(pady=10)
    tk.Button(tab_analysis, text="Select Log File and Scan", command=run_analysis, font=("Helvetica", 12)).pack(pady=10)
    tk.Button(tab_analysis, text="Start Real-Time Monitoring", command=start_monitoring, font=("Helvetica", 12)).pack(pady=10)
    tk.Button(tab_analysis, text="Stop Monitoring", command=stop_monitoring, font=("Helvetica", 12)).pack(pady=10)
    tk.Button(tab_analysis, text="Quit", command=quit_application, font=("Helvetica", 12)).pack(pady=10)

    analysis_results_frame = ttk.Frame(tab_analysis)
    analysis_results_frame.pack(pady=10, padx=10, fill='both', expand=True)

    # Status label for monitoring progress
    status_label = tk.Label(tab_analysis, text="Status: Idle", font=("Helvetica", 12))
    status_label.pack(pady=10)

    root.mainloop()

def run_analysis():
    log_file = filedialog.askopenfilename(title="Select Log File", filetypes=[("Log Files", "*.log *.evtx")])
    if not log_file:
        return

    suspicious_activity, total_lines = analyze_log_file(log_file)
    report_file = save_report(log_file, suspicious_activity, total_lines)
    
    result_message = f"Analysis complete!\nReport saved to: {report_file}"

    if suspicious_activity:
        alert_message = "Suspicious activity detected!"
        messagebox.showwarning("Alert", alert_message)
        
        # Plot the graph if suspicious activity is detected
        fig = plot_suspicious_activity(suspicious_activity)
        if fig:
            display_graph(fig)
    else:
        messagebox.showinfo("Analysis Complete", result_message)
    
    update_analysis_results(suspicious_activity, total_lines)


# Main function to start the GUI
if __name__ == '__main__':
    create_gui()
