#!/usr/bin/env python3
import whois
import dns.resolver
import requests
import socket
import ssl
import OpenSSL
from datetime import datetime
import json
import pandas as pd
import shodan
import subprocess

class DomainAnalyzer:
    def __init__(self, api_key=None):
        self.shodan_api = api_key
        self.results = {}
        
    def analyze_domain(self, domain):
        """Comprehensive domain analysis"""
        self.results['domain'] = domain
        self.results['timestamp'] = datetime.now().isoformat()
        
        # Collect WHOIS information
        self._get_whois(domain)
        
        # DNS analysis
        self._analyze_dns(domain)
        
        # SSL certificate analysis
        self._analyze_ssl(domain)
        
        # Headers analysis
        self._analyze_headers(domain)
        
        if self.shodan_api:
            self._shodan_lookup(domain)
            
    def _get_whois(self, domain):
        """Get WHOIS information"""
        try:
            w = whois.whois(domain)
            self.results['whois'] = {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'registrant': w.registrant,
                'admin_email': w.admin_email
            }
        except Exception as e:
            self.results['whois'] = {'error': str(e)}
            
    def _analyze_dns(self, domain):
        """Analyze DNS records"""
        dns_records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
        
        for record in record_types:
            try:
                answers = dns.resolver.resolve(domain, record)
                dns_records[record] = [str(answer) for answer in answers]
            except Exception:
                dns_records[record] = []
                
        self.results['dns'] = dns_records
        
    def _analyze_ssl(self, domain):
        """Analyze SSL certificate"""
        try:
            cert = ssl.get_server_certificate((domain, 443))
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
            
            self.results['ssl'] = {
                'issuer': dict(x509.get_issuer().get_components()),
                'subject': dict(x509.get_subject().get_components()),
                'expires': x509.get_notAfter().decode(),
                'serial_number': x509.get_serial_number(),
                'signature_algorithm': x509.get_signature_algorithm().decode()
            }
        except Exception as e:
            self.results['ssl'] = {'error': str(e)}
            
    def _analyze_headers(self, domain):
        """Analyze HTTP headers"""
        try:
            response = requests.get(f"https://{domain}", timeout=10)
            self.results['headers'] = dict(response.headers)
            self.results['server_info'] = {
                'status_code': response.status_code,
                'server': response.headers.get('Server', 'Unknown'),
                'powered_by': response.headers.get('X-Powered-By', 'Unknown')
            }
        except Exception as e:
            self.results['headers'] = {'error': str(e)}
            
    def _shodan_lookup(self, domain):
        """Perform Shodan lookup"""
        try:
            api = shodan.Shodan(self.shodan_api)
            results = api.search(domain)
            
            self.results['shodan'] = {
                'total_results': results['total'],
                'ports': list(set([r['port'] for r in results['matches']])),
                'vulnerabilities': [r.get('vulns', []) for r in results['matches']],
                'services': [r.get('product', '') for r in results['matches']]
            }
        except Exception as e:
            self.results['shodan'] = {'error': str(e)}
            
    def generate_report(self, output_format='json'):
        """Generate analysis report"""
        if output_format == 'json':
            return json.dumps(self.results, indent=2)
        elif output_format == 'csv':
            # Flatten nested dictionary for CSV export
            flat_dict = pd.json_normalize(self.results).to_dict(orient='records')[0]
            return pd.DataFrame([flat_dict])
        
    def security_assessment(self):
        """Assess security posture based on collected data"""
        assessment = {
            'risk_level': 'LOW',
            'findings': [],
            'recommendations': []
        }
        
        # Check SSL certificate
        if 'error' in self.results.get('ssl', {}):
            assessment['findings'].append('Invalid or missing SSL certificate')
            assessment['recommendations'].append('Implement valid SSL certificate')
            assessment['risk_level'] = 'HIGH'
            
        # Check security headers
        headers = self.results.get('headers', {})
        security_headers = [
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options'
        ]
        
        missing_headers = [h for h in security_headers if h not in headers]
        if missing_headers:
            assessment['findings'].append(f'Missing security headers: {missing_headers}')
            assessment['recommendations'].append('Implement missing security headers')
            assessment['risk_level'] = 'MEDIUM'
            
        # DNS security checks
        dns = self.results.get('dns', {})
        if not dns.get('TXT', []):
            assessment['findings'].append('Missing SPF/DMARC records')
            assessment['recommendations'].append('Implement email authentication')
        
        return assessment

def main():
    analyzer = DomainAnalyzer(api_key="YOUR_SHODAN_API_KEY")
    
    # Analyze domain
    domain = "example.com"
    analyzer.analyze_domain(domain)
    
    # Generate reports
    print("\nJSON Report:")
    print(analyzer.generate_report('json'))
    
    print("\nSecurity Assessment:")
    print(json.dumps(analyzer.security_assessment(), indent=2))
    
    # Export to CSV
    csv_report = analyzer.generate_report('csv')
    csv_report.to_csv(f"{domain}_analysis.csv", index=False)

if __name__ == "__main__":
    main()
