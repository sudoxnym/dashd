#!/usr/bin/env python3
"""
mail proxy for dashd - fetches emails via IMAP, sends via SMTP
endpoints:
  POST /api/mail/inbox - list emails
  POST /api/mail/read/<id> - get full email + thread
  POST /api/mail/send - send reply
"""

import imaplib
import smtplib
import email
from email.header import decode_header
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import ssl
import re
from datetime import datetime

class MailProxyHandler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8')

        try:
            data = json.loads(body)
            server = data.get('server', '')
            user = data.get('user', '')
            password = data.get('pass', '')

            if self.path.startswith('/api/mail/inbox'):
                limit = 10
                if 'limit=' in self.path:
                    try:
                        limit = int(self.path.split('limit=')[-1].split('&')[0])
                    except:
                        pass
                messages = fetch_emails(server, user, password, limit)
                self.send_json(messages)

            elif self.path.startswith('/api/mail/read/'):
                msg_id = self.path.split('/api/mail/read/')[-1].split('?')[0]
                email_data = fetch_full_email(server, user, password, msg_id)
                self.send_json(email_data)

            elif self.path.startswith('/api/mail/thread/'):
                msg_id = self.path.split('/api/mail/thread/')[-1].split('?')[0]
                thread = fetch_thread(server, user, password, msg_id)
                self.send_json(thread)

            elif self.path == '/api/mail/send':
                to = data.get('to', '')
                subject = data.get('subject', '')
                body_text = data.get('body', '')
                in_reply_to = data.get('in_reply_to', '')
                references = data.get('references', '')
                result = send_email(server, user, password, to, subject, body_text, in_reply_to, references)
                self.send_json(result)

            else:
                self.send_error(404, 'Not found')

        except Exception as e:
            self.send_json({'error': str(e)}, 500)

    def send_json(self, data, status=200):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def send_error(self, code, message):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps({'error': message}).encode())

    def log_message(self, format, *args):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {args[0]}")

def decode_mime_header(header):
    if not header:
        return ''
    decoded = decode_header(header)
    result = []
    for part, charset in decoded:
        if isinstance(part, bytes):
            try:
                result.append(part.decode(charset or 'utf-8', errors='replace'))
            except:
                result.append(part.decode('utf-8', errors='replace'))
        else:
            result.append(part)
    return ''.join(result)

def get_email_body(msg):
    """extract plain text body from email message"""
    body = ''
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get('Content-Disposition', ''))
            if content_type == 'text/plain' and 'attachment' not in content_disposition:
                try:
                    charset = part.get_content_charset() or 'utf-8'
                    body = part.get_payload(decode=True).decode(charset, errors='replace')
                    break
                except:
                    pass
            elif content_type == 'text/html' and not body and 'attachment' not in content_disposition:
                try:
                    charset = part.get_content_charset() or 'utf-8'
                    html = part.get_payload(decode=True).decode(charset, errors='replace')
                    # strip html tags for plain display
                    body = re.sub('<[^<]+?>', '', html)
                    body = re.sub(r'\s+', ' ', body).strip()
                except:
                    pass
    else:
        try:
            charset = msg.get_content_charset() or 'utf-8'
            body = msg.get_payload(decode=True).decode(charset, errors='replace')
        except:
            body = str(msg.get_payload())
    return body.strip()

def fetch_emails(server, user, password, limit=10):
    messages = []
    try:
        context = ssl.create_default_context()
        imap = imaplib.IMAP4_SSL(server, 993, ssl_context=context)
        imap.login(user, password)
        imap.select('INBOX')

        status, data = imap.search(None, 'ALL')
        if status != 'OK':
            return messages

        message_ids = data[0].split()
        recent_ids = message_ids[-limit:] if len(message_ids) > limit else message_ids
        recent_ids = list(reversed(recent_ids))

        for msg_id in recent_ids:
            status, msg_data = imap.fetch(msg_id, '(FLAGS RFC822.HEADER)')
            if status != 'OK':
                continue

            flags_data = msg_data[0][0].decode() if msg_data[0][0] else ''
            is_read = '\\Seen' in flags_data

            header_data = msg_data[0][1]
            msg = email.message_from_bytes(header_data)

            from_addr = decode_mime_header(msg.get('From', ''))
            if '<' in from_addr:
                from_addr = from_addr.split('<')[0].strip().strip('"')

            subject = decode_mime_header(msg.get('Subject', '(no subject)'))
            date_str = msg.get('Date', '')

            try:
                from email.utils import parsedate_to_datetime
                dt = parsedate_to_datetime(date_str)
                date_display = dt.strftime('%b %d')
            except:
                date_display = date_str[:10] if date_str else ''

            messages.append({
                'id': msg_id.decode(),
                'from': from_addr[:30] + '...' if len(from_addr) > 30 else from_addr,
                'subject': subject[:50] + '...' if len(subject) > 50 else subject,
                'date': date_display,
                'read': is_read
            })

        imap.logout()
    except Exception as e:
        print(f"IMAP error: {e}")
        raise

    return messages

def fetch_full_email(server, user, password, msg_id):
    """fetch complete email with body"""
    try:
        context = ssl.create_default_context()
        imap = imaplib.IMAP4_SSL(server, 993, ssl_context=context)
        imap.login(user, password)
        imap.select('INBOX')

        status, msg_data = imap.fetch(msg_id.encode(), '(RFC822)')
        if status != 'OK':
            return {'error': 'message not found'}

        raw_email = msg_data[0][1]
        msg = email.message_from_bytes(raw_email)

        from_addr = decode_mime_header(msg.get('From', ''))
        from_email = ''
        if '<' in from_addr:
            match = re.search(r'<([^>]+)>', from_addr)
            if match:
                from_email = match.group(1)
            from_name = from_addr.split('<')[0].strip().strip('"')
        else:
            from_email = from_addr
            from_name = from_addr

        to_addr = decode_mime_header(msg.get('To', ''))
        subject = decode_mime_header(msg.get('Subject', ''))
        date_str = msg.get('Date', '')
        message_id = msg.get('Message-ID', '')
        references = msg.get('References', '')
        in_reply_to = msg.get('In-Reply-To', '')

        try:
            from email.utils import parsedate_to_datetime
            dt = parsedate_to_datetime(date_str)
            date_display = dt.strftime('%b %d, %Y at %I:%M %p')
        except:
            date_display = date_str

        body = get_email_body(msg)

        # mark as read
        imap.store(msg_id.encode(), '+FLAGS', '\\Seen')
        imap.logout()

        return {
            'id': msg_id,
            'from_name': from_name,
            'from_email': from_email,
            'to': to_addr,
            'subject': subject,
            'date': date_display,
            'body': body,
            'message_id': message_id,
            'references': references,
            'in_reply_to': in_reply_to
        }

    except Exception as e:
        print(f"fetch error: {e}")
        return {'error': str(e)}

def fetch_thread(server, user, password, msg_id):
    """fetch email thread based on references/subject"""
    try:
        # first get the target message to find thread references
        target = fetch_full_email(server, user, password, msg_id)
        if 'error' in target:
            return [target]

        context = ssl.create_default_context()
        imap = imaplib.IMAP4_SSL(server, 993, ssl_context=context)
        imap.login(user, password)
        imap.select('INBOX')

        thread = []
        subject_base = re.sub(r'^(Re:\s*|Fwd:\s*)+', '', target['subject'], flags=re.IGNORECASE).strip()

        # search by subject
        search_subject = subject_base.replace('"', '\\"')[:50]
        status, data = imap.search(None, f'SUBJECT "{search_subject}"')

        if status == 'OK' and data[0]:
            thread_ids = data[0].split()[-10:]  # limit to 10 messages
            for tid in thread_ids:
                status, msg_data = imap.fetch(tid, '(RFC822.HEADER)')
                if status != 'OK':
                    continue

                header_data = msg_data[0][1]
                msg = email.message_from_bytes(header_data)

                from_addr = decode_mime_header(msg.get('From', ''))
                if '<' in from_addr:
                    from_addr = from_addr.split('<')[0].strip().strip('"')

                date_str = msg.get('Date', '')
                try:
                    from email.utils import parsedate_to_datetime
                    dt = parsedate_to_datetime(date_str)
                    date_display = dt.strftime('%b %d %I:%M %p')
                    timestamp = dt.timestamp()
                except:
                    date_display = date_str[:16]
                    timestamp = 0

                thread.append({
                    'id': tid.decode(),
                    'from': from_addr,
                    'date': date_display,
                    'timestamp': timestamp,
                    'current': tid.decode() == msg_id
                })

        imap.logout()

        # sort by timestamp
        thread.sort(key=lambda x: x.get('timestamp', 0))
        return thread

    except Exception as e:
        print(f"thread error: {e}")
        return [{'error': str(e)}]

def send_email(server, user, password, to, subject, body, in_reply_to='', references=''):
    """send email via SMTP"""
    try:
        msg = MIMEMultipart()
        msg['From'] = user
        msg['To'] = to
        msg['Subject'] = subject

        if in_reply_to:
            msg['In-Reply-To'] = in_reply_to
        if references:
            msg['References'] = references + ' ' + in_reply_to if in_reply_to else references

        msg.attach(MIMEText(body, 'plain'))

        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(server, 465, context=context) as smtp:
            smtp.login(user, password)
            smtp.send_message(msg)

        return {'success': True, 'message': 'email sent'}

    except Exception as e:
        print(f"SMTP error: {e}")
        return {'error': str(e)}

if __name__ == '__main__':
    port = 8087
    server = HTTPServer(('0.0.0.0', port), MailProxyHandler)
    print(f"mail proxy running on port {port}")
    print("endpoints:")
    print(f"  POST /api/mail/inbox?limit=N")
    print(f"  POST /api/mail/read/<id>")
    print(f"  POST /api/mail/thread/<id>")
    print(f"  POST /api/mail/send")
    server.serve_forever()
