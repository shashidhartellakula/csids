import smtplib
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text      import MIMEText
from email.mime.base      import MIMEBase
from email                import encoders


def send_alert_email(to_email, username, alerts):
    smtp_host = os.environ.get("CSIDS_SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.environ.get("CSIDS_SMTP_PORT", 587))
    smtp_user = os.environ.get("CSIDS_SMTP_USER", "")
    smtp_pass = os.environ.get("CSIDS_SMTP_PASS", "")

    if not smtp_user or not smtp_pass:
        print("[NOTIFIER] SMTP not configured — skipping email")
        return False

    high   = [a for a in alerts if (a.get('risk_score') or 0) >= 6]
    medium = [a for a in alerts if 3 <= (a.get('risk_score') or 0) < 6]
    low    = [a for a in alerts if (a.get('risk_score') or 0) < 3]

    rows_html = ''.join([
        f"""<tr style="background:{'#fff5f5' if (a.get('risk_score') or 0)>=6 
            else '#fffbf0' if (a.get('risk_score') or 0)>=3 else 'white'};">
            <td style="padding:10px;font-family:monospace;font-size:12px;
                max-width:200px;overflow:hidden;">
                {a.get('sequence','')}
            </td>
            <td style="padding:10px;font-weight:bold;
                color:{'#ff3864' if (a.get('risk_score') or 0)>=6 
                else '#ff8c00' if (a.get('risk_score') or 0)>=3 
                else '#00b894'};">
                {float(a.get('risk_score', 0)):.1f}
            </td>
            <td style="padding:10px;color:#666;font-size:12px;">
                {a.get('reason','')}
            </td>
        </tr>"""
        for a in alerts[:10]
    ])

    body = f"""
    <html><body style="font-family:Arial,sans-serif;background:#f4f4f4;padding:20px;">
    <div style="max-width:600px;margin:auto;background:white;
                border-radius:8px;overflow:hidden;box-shadow:0 2px 10px rgba(0,0,0,0.1);">

        <div style="background:#0a1628;padding:24px;text-align:center;">
            <h1 style="color:#00d4ff;font-family:monospace;
                       letter-spacing:4px;margin:0;">CSIDS</h1>
            <p style="color:#5a7a9a;margin:6px 0 0;font-size:13px;">
                Command Sequence Intrusion Detection System
            </p>
        </div>

        <div style="padding:24px;">
            <div style="background:#fff3cd;border:1px solid #ffc107;
                        border-radius:6px;padding:14px;margin-bottom:20px;">
                <strong>⚠ Intrusion activity detected for user:
                    <span style="color:#d63031;">{username}</span>
                </strong><br>
                <span style="font-size:12px;color:#666;">
                    Please review the details below and take action immediately.
                </span>
            </div>

            <table style="width:100%;border-collapse:collapse;
                          margin-bottom:20px;text-align:center;">
                <tr>
                    <td style="background:#ff3864;color:white;padding:16px;
                               border-radius:4px;width:32%;">
                        <div style="font-size:28px;font-weight:bold;">{len(high)}</div>
                        <div style="font-size:11px;margin-top:4px;">HIGH RISK</div>
                    </td>
                    <td style="width:2%;"></td>
                    <td style="background:#ff8c00;color:white;padding:16px;
                               border-radius:4px;width:32%;">
                        <div style="font-size:28px;font-weight:bold;">{len(medium)}</div>
                        <div style="font-size:11px;margin-top:4px;">MEDIUM RISK</div>
                    </td>
                    <td style="width:2%;"></td>
                    <td style="background:#00b894;color:white;padding:16px;
                               border-radius:4px;width:32%;">
                        <div style="font-size:28px;font-weight:bold;">{len(low)}</div>
                        <div style="font-size:11px;margin-top:4px;">LOW RISK</div>
                    </td>
                </tr>
            </table>

            <h3 style="color:#0a1628;border-bottom:2px solid #00d4ff;
                       padding-bottom:8px;margin-bottom:16px;">
                Alert Details
            </h3>

            <table style="width:100%;border-collapse:collapse;font-size:13px;">
                <thead>
                    <tr style="background:#0a1628;color:white;">
                        <th style="padding:10px;text-align:left;">Sequence</th>
                        <th style="padding:10px;text-align:left;">Score</th>
                        <th style="padding:10px;text-align:left;">Reason</th>
                    </tr>
                </thead>
                <tbody>{rows_html}</tbody>
            </table>

            {'<p style="color:#999;font-size:12px;margin-top:8px;">Showing first 10 alerts. Full report attached as PDF.</p>' if len(alerts) > 10 else ''}

            <div style="margin-top:24px;padding:14px;background:#f8f9fa;
                        border-radius:6px;font-size:12px;color:#666;
                        border-left:3px solid #00d4ff;">
                This is an automated security alert from CSIDS.<br>
                A detailed PDF report is attached to this email.
            </div>
        </div>
    </div>
    </body></html>
    """

    msg            = MIMEMultipart('mixed')
    msg['Subject'] = f"🚨 CSIDS Security Alert — Intrusion Detected for {username}"
    msg['From']    = smtp_user
    msg['To']      = to_email
    msg.attach(MIMEText(body, 'html'))

    # attach PDF
    try:
        from pdf_report       import generate_pdf_report
        from detector.profiler import get_profile_stats

        stats     = get_profile_stats(username)
        pdf_bytes = generate_pdf_report(username, alerts, stats)

        pdf_part = MIMEBase('application', 'octet-stream')
        pdf_part.set_payload(pdf_bytes)
        encoders.encode_base64(pdf_part)
        pdf_part.add_header(
            'Content-Disposition',
            f'attachment; filename="csids_report_{username}.pdf"'
        )
        msg.attach(pdf_part)
        print(f"[NOTIFIER] PDF attached for {username}")

    except Exception as e:
        print(f"[NOTIFIER] PDF attachment failed: {e}")

    # send email
    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.ehlo()
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_user, to_email, msg.as_string())
        print(f"[NOTIFIER] ✅ Email sent to {to_email}")
        return True
    except Exception as e:
        print(f"[NOTIFIER] ❌ Email failed: {e}")
        return False