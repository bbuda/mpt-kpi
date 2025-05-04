import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_reset_email(to_email, reset_url):
    sender_email = "your_email@example.com"
    sender_password = "your_password"

    msg = MIMEMultipart()
    msg["From"] = sender_email
    msg["To"] = to_email
    msg["Subject"] = "Password Reset"

    body = f"""
    <html>
        <body>
            <p>To reset your password, click the link below:</p>
            <a href='{reset_url}'>Reset Password</a>
        </body>
    </html>
    """
    msg.attach(MIMEText(body, "html"))

    try:
        with smtplib.SMTP("smtp.example.com", 587) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, to_email, msg.as_string())
    except Exception as e:
        print("Failed to send email:", e)
