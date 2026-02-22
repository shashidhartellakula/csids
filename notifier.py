"""
CSIDS Email Notifier
Sends alert emails via SMTP (Gmail, Outlook, etc.)

Configure by setting environment variables or using the Settings page:
    CSIDS_SMTP_HOST  — default: smtp.gmail.com
    CSIDS_SMTP_PORT  — default: 587
    CSIDS_SMTP_USER  — your email address
    CSIDS_SMTP_PASS  — your app password
"""
import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime


def get_smtp_config():
    return {
        "host":     os.environ.get("CSIDS_SMTP_HOST", "smtp.gmail.com"),
        "port":     int(os.environ.get("CSIDS_SMTP_PORT", "587")),
        "user":     os.environ.get("CSIDS_SMTP_USER", ""),
        "password": os.environ.get("CSIDS_SMTP_PASS", ""),
        "from":     os.environ.get("CSIDS_SMTP_USER", "csids@localhost"),
    }


def send_alert_email(to_email, user, alerts):
    """
    Send an intrusion alert email.
    Returns True if sent, False if failed or not configured.
    """
    config = get_smtp_config()

    if not config["user"] or not config["password"]:
        print("[Notifier] SMTP not configured — skipping email.")
        return False

    subject = f"🚨 CSIDS Alert: {len(alerts)} intrusion(s) detected for '{user}'"

    # build alert rows for the HTML table
    alert_rows = ""
    for a in alerts:
        rs    = a.get("risk_score", 0)
        color = "#ff3864" if rs >= 6 else "#ff8c00" if rs >= 3 else "#00c97a"
        cmds  = ", ".join(a.get("risky", []))
        alert_rows += f"""
        <tr>
            <td style="padding:8px;border:1px solid #1e3a5f;
                       font-family:monospace;font-size:12px;
                       color:#c8d8f0;">{a.get('sequence','')}</td>
            <td style="padding:8px;border:1px solid #1e3a5f;
                       font-size:12px;color:#8a9ab0;">{a.get('reason','')}</td>
            <td style="padding:8px;border:1px solid #1e3a5f;
                       color:{color};font-weight:bold;
                       font-family:monospace;">{rs}/10</td>
            <td style="padding:8px;border:1px solid #1e3a5f;
                       font-size:12px;color:#ff3864;">{cmds}</td>
        </tr>
        """

    html = f"""
    <html>
    <body style="font-family:sans-serif;background:#090e1a;
                 color:#c8d8f0;padding:24px;margin:0;">
      <div style="max-width:680px;margin:auto;background:#0f1e38;
                  border-radius:8px;border:1px solid #1e3a5f;
                  overflow:hidden;">

        <!-- header -->
        <div style="background:#0a1628;padding:24px 28px;
                    border-bottom:2px solid #00d4ff;">
          <div style="font-family:monospace;font-size:24px;
                      color:#00d4ff;letter-spacing:4px;">CSIDS</div>
          <div style="font-size:11px;color:#5a7a9a;
                      letter-spacing:2px;margin-top:4px;">
              INTRUSION DETECTION ALERT
          </div>
        </div>

        <!-- body -->
        <div style="padding:24px 28px;">
          <p style="color:#ff3864;font-size:18px;font-weight:bold;margin-bottom:16px;">
              🚨 {len(alerts)} intrusion(s) detected
          </p>
          <p style="margin-bottom:6px;">
              <b>User:</b>
              <span style="font-family:monospace;color:#00d4ff;">{user}</span>
          </p>
          <p style="margin-bottom:20px;">
              <b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
          </p>

          <table style="width:100%;border-collapse:collapse;">
            <thead>
              <tr style="background:#0a1628;">
                <th style="padding:10px 8px;border:1px solid #1e3a5f;
                           text-align:left;font-size:11px;
                           color:#5a7a9a;letter-spacing:1px;">SEQUENCE</th>
                <th style="padding:10px 8px;border:1px solid #1e3a5f;
                           text-align:left;font-size:11px;
                           color:#5a7a9a;letter-spacing:1px;">REASON</th>
                <th style="padding:10px 8px;border:1px solid #1e3a5f;
                           text-align:left;font-size:11px;
                           color:#5a7a9a;letter-spacing:1px;">RISK</th>
                <th style="padding:10px 8px;border:1px solid #1e3a5f;
                           text-align:left;font-size:11px;
                           color:#5a7a9a;letter-spacing:1px;">COMMANDS</th>
              </tr>
            </thead>
            <tbody>{alert_rows}</tbody>
          </table>

          <p style="margin-top:20px;font-size:12px;color:#5a7a9a;">
            This alert was generated automatically by CSIDS.<br>
            Review your system immediately if this activity is unexpected.
          </p>
        </div>

        <!-- footer -->
        <div style="padding:14px 28px;border-top:1px solid #1e3a5f;
                    font-size:11px;color:#5a7a9a;text-align:center;">
            CSIDS v2.0 — Command Sequence Intrusion Detection System
        </div>

      </div>
    </body>
    </html>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = config["from"]
    msg["To"]      = to_email
    msg.attach(MIMEText(html, "html"))

    try:
        with smtplib.SMTP(config["host"], config["port"]) as server:
            server.starttls()
            server.login(config["user"], config["password"])
            server.sendmail(config["from"], to_email, msg.as_string())
        print(f"[Notifier] Alert email sent to {to_email}")
        return True
    except Exception as e:
        print(f"[Notifier] Failed to send email: {e}")
        return False