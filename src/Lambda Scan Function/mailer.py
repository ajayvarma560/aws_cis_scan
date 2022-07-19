import smtplib
import sys
import os

from email import encoders
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate
from jinja2 import Environment, FileSystemLoader

def send_email(subject, body_text, to_emails,
                               file_to_attach):
    """
    Send an email with an attachment
    """
    # extract server and from_addr from config
    host = os.environ['MAIL_SERVER']
    port = os.environ['MAIL_PORT']
    username = os.environ['MAIL_USERNAME']
    password = os.environ['MAIL_PASSWORD']
    from_addr = os.environ['FROM_ADDR']

    # create the message
    msg = MIMEMultipart()
    msg["From"] = from_addr
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=True)
    if body_text:
        msg.attach( MIMEText(body_text, 'html') )

    msg["To"] = ', '.join(to_emails)

    if file_to_attach:
        header = 'Content-Disposition', 'attachment; filename=scan.html'
        attachment = MIMEBase('application', "octet-stream")
        try:
            with open(file_to_attach, "rb") as fh:
                data = fh.read()
            attachment.set_payload( data )
            encoders.encode_base64(attachment)
            attachment.add_header(*header)
            msg.attach(attachment)
        except IOError:
            msg = "Error opening attachment file %s" % file_to_attach
            print(msg)
            sys.exit(1)

    emails = to_emails

    server = smtplib.SMTP(host,port)
    server.starttls()
    server.login(username, password)
    server.sendmail(from_addr, emails, msg.as_string())
    server.quit()

def send_notification(user, subject, body, recipients, file_to_attach=None):
    context = {'name' : user, 'body' : body}
    env = Environment(loader=FileSystemLoader('templates/'))
    template = env.get_template('email_template.html')
    body_text = template.render(context=context)
    send_email(subject, body_text, recipients,
                               file_to_attach)    
    return "Mail sent successfully."

if __name__ == "__main__":
    emails = ["example@email.com"]
    subject = "Test email with attachment from Python"
    body = "This is an test email"
    file_path = "AWS_CIS_Report_account_number_CIS.html"
    name = "tester"
    send_notification(name, subject, body, emails, file_path)