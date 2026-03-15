import re
import math
from urllib.parse import urlparse
from collections import Counter

class URLFeatureExtractor:
    """Extracts structural and lexical features directly from a URL string."""
    
    # Common words found in phishing URLs
    SUSPICIOUS_WORDS = ['login', 'secure', 'account', 'update', 'banking', 'paypal', 'verify', 'webscr', 'signin', 'free']

    @staticmethod
    def extract_features(url: str) -> list:
        if not url.startswith('http'):
            url = 'http://' + url
            
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        
        return [
            URLFeatureExtractor.get_url_length(url),
            URLFeatureExtractor.get_domain_length(domain),
            URLFeatureExtractor.count_dots(domain),
            URLFeatureExtractor.count_hyphens(domain),
            URLFeatureExtractor.has_at_symbol(url),
            URLFeatureExtractor.has_double_slash_in_path(path),
            URLFeatureExtractor.count_subdomains(domain),
            URLFeatureExtractor.is_ip_address(domain),
            URLFeatureExtractor.count_suspicious_words(url),
            URLFeatureExtractor.calculate_entropy(domain),
            URLFeatureExtractor.count_special_chars(url)
        ]

    @staticmethod
    def get_url_length(url): return len(url)
    
    @staticmethod
    def get_domain_length(domain): return len(domain)
    
    @staticmethod
    def count_dots(domain): return domain.count('.')
    
    @staticmethod
    def count_hyphens(domain): return domain.count('-')
    
    @staticmethod
    def has_at_symbol(url): return 1 if '@' in url else 0
    
    @staticmethod
    def has_double_slash_in_path(path): return 1 if '//' in path else 0
    
    @staticmethod
    def count_subdomains(domain):
        # basic approximation: count dots in domain minus 1 (for the TLD)
        dots = domain.count('.')
        return max(0, dots - 1)
        
    @staticmethod
    def is_ip_address(domain):
        # Remove port if exists
        domain = domain.split(':')[0]
        match = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain)
        return 1 if match else 0
        
    @staticmethod
    def count_suspicious_words(url):
        url_lower = url.lower()
        return sum(1 for word in URLFeatureExtractor.SUSPICIOUS_WORDS if word in url_lower)
        
    @staticmethod
    def calculate_entropy(string):
        """Calculates Shannon entropy to detect random strings."""
        if not string: return 0
        p, lns = Counter(string), float(len(string))
        return -sum(count/lns * math.log(count/lns, 2) for count in p.values())
        
    @staticmethod
    def count_special_chars(url):
        special_chars = ['?', '=', '&', '%', '_', '~']
        return sum(url.count(c) for c in special_chars)
