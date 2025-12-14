#!/usr/bin/env python3
"""
browser proxy for dashd - strips X-Frame-Options to allow embedding any page
runs on port 8088
usage: /proxy?url=https://example.com
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import urllib.request
import urllib.error
import ssl
import re

class ProxyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if not self.path.startswith('/proxy'):
            self.send_error(404, 'use /proxy?url=...')
            return
        
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        
        if 'url' not in params:
            self.send_error(400, 'missing url parameter')
            return
        
        target_url = params['url'][0]
        
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            req = urllib.request.Request(target_url, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            
            with urllib.request.urlopen(req, context=ctx, timeout=10) as response:
                content_type = response.headers.get('Content-Type', 'text/html')
                body = response.read()
                
                if 'text/html' in content_type:
                    body_str = body.decode('utf-8', errors='replace')
                    base_tag = '<base href="' + target_url + '">'
                    if '<head>' in body_str.lower():
                        body_str = re.sub(r'(<head[^>]*>)', r'\1' + base_tag, body_str, count=1, flags=re.IGNORECASE)
                    elif '<html>' in body_str.lower():
                        body_str = re.sub(r'(<html[^>]*>)', r'\1<head>' + base_tag + '</head>', body_str, count=1, flags=re.IGNORECASE)
                    body = body_str.encode('utf-8')
                
                self.send_response(200)
                self.send_header('Content-Type', content_type)
                self.send_header('Access-Control-Allow-Origin', '*')
                self.send_header('Content-Length', len(body))
                self.end_headers()
                self.wfile.write(body)
                
        except urllib.error.HTTPError as e:
            self.send_error(e.code, str(e.reason))
        except Exception as e:
            self.send_error(500, str(e))
    
    def log_message(self, format, *args):
        pass

if __name__ == '__main__':
    port = 8088
    server = HTTPServer(('0.0.0.0', port), ProxyHandler)
    print(f'browser proxy running on port {port}')
    server.serve_forever()
