import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import re
import matplotlib.pyplot as plt
from collections import defaultdict
import json
import os
from Evtx.Evtx import Evtx
from xml.etree import ElementTree as ET
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import threading
import time
from sklearn.ensemble import IsolationForest
from sklearn.cluster import KMeans
from collections import deque
import smtplib
from email.mime.text import MIMEText

# Predefined patterns with severity levels
patterns = {
    'Failed Login': (re.compile(r'failed login|authentication failure', re.IGNORECASE), 'Medium'),
    'Unauthorized Access': (re.compile(r'unauthorized access|access denied|permission denied', re.IGNORECASE), 'High'),
    'Privilege Escalation': (re.compile(r'privilege escalation|root access|admin rights granted', re.IGNORECASE), 'Critical'),
    'Malicious Execution': (re.compile(r'malicious|script executed|suspicious command', re.IGNORECASE), 'Critical'),
    'File Tampering': (re.compile(r'file modified|file tampered|unexpected change', re.IGNORECASE), 'High'),
}

# Remedies for each suspicious activity
remedies = {
    'Failed Login': "Review the failed login attempts and investigate for possible brute-force attacks.",
    'Unauthorized Access': "Check system logs for unauthorized access attempts and change access policies if necessary.",
    'Privilege Escalation': "Investigate the source of privilege escalation and verify if it was intentional.",
    'Malicious Execution': "Inspect the executed scripts or commands for malicious behavior and isolate if needed.",
    'File Tampering': "Verify the integrity of the modified files and restore them if unexpected changes are found."
}

config_file = 'log_analyzer_config.json'

# ML Models
isolation_forest = IsolationForest(contamination=0.1, random_state=42)
kmeans = KMeans(n_clusters=3, random_state=42)

# Initialize tracking structures
event_window = deque(maxlen=100)
time_window = deque(maxlen=100)
user_actions = defaultdict(list)
event_timestamps = defaultdict(list)

# Dynamic severity ranking system
severity_thresholds = {
    'Low': 30,
    'Medium': 80,
    'High': 150,
    'Critical': 250
}

# Real-time risk score
risk_score = 0

# Create a threading event to signal when to stop monitoring
stop_event = threading.Event()

def load_patterns():
    global patterns, remedies
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            config = json.load(f)
            patterns.update({k: (re.compile(v, re.IGNORECASE), severity) for k, (v, severity) in config.get('patterns', {}).items()})
            remedies.update(config.get('remedies', {}))

def save_patterns():
    config = {
        'patterns': {k: (v[0].pattern, v[1]) for k, v in patterns.items()},
        'remedies': remedies
    }
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=4)

def analyze_log_file(log_file):
    suspicious_activity = defaultdict(lambda: [0, [], ''])
    total_lines = 0

    try:
        if log_file.endswith('.log'):
            with open(log_file, 'r') as f:
                for line in f:
                    total_lines += 1
                    for activity, (pattern, severity) in patterns.items():
                        if pattern.search(line):
                            suspicious_activity[activity][0] += 1
                            suspicious_activity[activity][1].append(line.strip())
                            suspicious_activity[activity][2] = severity
        elif log_file.endswith('.evtx'):
            with Evtx(log_file) as evtx:
                for record in evtx.records():
                    total_lines += 1
                    try:
                        xml_content = ET.fromstring(record.xml())
                        event_data = "".join(xml_content.itertext())
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

def save_report(log_file, suspicious_activity, total_lines):
    report_file = log_file.replace('.log', '_output.txt').replace('.evtx', '_output.txt')
    with open(report_file, 'w') as f:
        f.write(f'Total lines processed: {total_lines}\n\n')
        if suspicious_activity:
            for activity, (count, logs, severity) in suspicious_activity.items():
                f.write(f'{activity} (Severity: {severity}): {count}\n')
                f.write(f'{remedies.get(activity, "No remedy available")}\n\n')
                f.write(f"Example log lines:\n")
                for log in logs[:5]:
                    f.write(f"  - {log}\n")
                f.write("\n")
        else:
            f.write('No suspicious activity detected.\n')
    return report_file

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

def send_email(report_file):
    sender_email = "mohandevu@gmail.com"  # Replace with your email
    receiver_email = "mohandevu1984@gmail.com"  # Replace with recipient's email
    password = "Interc00l3r@123"  # Replace with your email password

    subject = "Log Analysis Report"
    body = f"Please find the attached log analysis report: {report_file}"

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = sender_email
    msg['To'] = receiver_email

    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, msg.as_string())
            messagebox.showinfo("Success", "Email sent successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to send email: {str(e)}")

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

        fig = plot_suspicious_activity(suspicious_activity)
        if fig:
            display_graph(fig)
    else:
        messagebox.showinfo("Analysis Complete", result_message)
    
    update_analysis_results(suspicious_activity, total_lines)

    # Send email option
    if messagebox.askyesno("Send Email", "Do you want to send the report via email?"):
        send_email(report_file)

def display_graph(fig):
    canvas = FigureCanvasTkAgg(fig, master=tab_analysis)
    canvas.draw()
    canvas.get_tk_widget().pack(pady=10, fill=tk.BOTH, expand=True)

def update_analysis_results(suspicious_activity, total_lines):
    for widget in analysis_results_frame.winfo_children():
        widget.destroy()

    tk.Label(analysis_results_frame, text=f"Total lines processed: {total_lines}", font=("Helvetica", 12)).pack(pady=5)
    tk.Label(analysis_results_frame, text=f"Real-time Risk Score: {risk_score}", font=("Helvetica", 12)).pack(pady=5)

    if suspicious_activity:
        for activity, (count, logs, severity) in suspicious_activity.items():
            tk.Label(analysis_results_frame, text=f'{activity} (Severity: {severity}): {count}', font=("Helvetica", 12)).pack(pady=2)
            tk.Label(analysis_results_frame, text=f'{remedies.get(activity, "No remedy available")}', font=("Helvetica", 12)).pack(pady=2)

def monitor_logs():
    default_log_path = os.path.join(os.environ['SystemRoot'], 'System32', 'winevt', 'Logs')  # Default path for event logs
    while not stop_event.is_set():
        # Placeholder for real log monitoring logic
        print("Monitoring logs...")  # Replace with actual logic

        # Here, you can implement the logic to analyze logs in the default_log_path and update risk_score
        global risk_score
        # Dummy logic for risk score change
        risk_score = (risk_score + 5) % 300
        
        update_monitoring_stats()  # Update the GUI
        time.sleep(5)  # Adjust the sleep time as necessary

def update_monitoring_stats():
    for widget in monitoring_frame.winfo_children():
        widget.destroy()
    tk.Label(monitoring_frame, text=f"Real-time Risk Score: {risk_score}", font=("Helvetica", 12)).pack(pady=5)

def start_monitoring():
    stop_event.clear()
    monitoring_thread = threading.Thread(target=monitor_logs)
    monitoring_thread.start()

def stop_monitoring():
    stop_event.set()

# GUI Setup
root = tk.Tk()
root.title("Log Analyzer")
root.geometry("800x600")

# Create tabs
tab_control = ttk.Notebook(root)
tab_analysis = ttk.Frame(tab_control)
tab_monitoring = ttk.Frame(tab_control)

tab_control.add(tab_analysis, text='Log Analysis')
tab_control.add(tab_monitoring, text='Real-Time Monitoring')
tab_control.pack(expand=1, fill='both')

# Log Analysis Frame
analyze_button = tk.Button(tab_analysis, text="Analyze Log File", command=run_analysis)
analyze_button.pack(pady=10)

analysis_results_frame = tk.Frame(tab_analysis)
analysis_results_frame.pack(pady=10, fill=tk.BOTH, expand=True)

# Real-Time Monitoring Frame
monitoring_frame = tk.Frame(tab_monitoring)
monitoring_frame.pack(pady=10, fill=tk.BOTH, expand=True)

start_monitor_button = tk.Button(tab_monitoring, text="Start Monitoring", command=start_monitoring)
start_monitor_button.pack(pady=5)

stop_monitor_button = tk.Button(tab_monitoring, text="Stop Monitoring", command=stop_monitoring)
stop_monitor_button.pack(pady=5)

load_patterns()  # Load patterns from the config file

root.mainloop()
