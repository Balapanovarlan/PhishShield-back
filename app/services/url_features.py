import re
import math
from urllib.parse import urlparse
from collections import Counter

class URLFeatureExtractor:
    """Extracts structural and lexical features from a URL string, stripping protocols to improve model accuracy."""
    
    # Common words found in phishing URLs
    SUSPICIOUS_WORDS = ['login', 'secure', 'account', 'update', 'banking', 'paypal', 'verify', 'webscr', 'signin', 'free']

    @staticmethod
    def extract_features(url: str) -> list:
        # Clean the URL to avoid skewed length calculations
        # Removing protocol (http://, https://) and www prefix
        clean_url = re.sub(r'^https?://', '', url, flags=re.IGNORECASE)
        clean_url = re.sub(r'^www\.', '', clean_url, flags=re.IGNORECASE)
        
        # Ensure urlparse still works correctly for other parts
        full_url = url if url.startswith('http') else 'http://' + url
        parsed = urlparse(full_url)
        
        domain = parsed.netloc
        # Clean domain as well for length and subdomain calculations
        clean_domain = re.sub(r'^www\.', '', domain, flags=re.IGNORECASE)
        path = parsed.path
        
        return [
            URLFeatureExtractor.get_url_length(clean_url), # Clean length!
            URLFeatureExtractor.get_domain_length(clean_domain), # Clean domain length!
            URLFeatureExtractor.count_dots(clean_domain),
            URLFeatureExtractor.count_hyphens(clean_domain),
            URLFeatureExtractor.has_at_symbol(clean_url),
            URLFeatureExtractor.has_double_slash_in_path(path),
            URLFeatureExtractor.count_subdomains(clean_domain),
            URLFeatureExtractor.is_ip_address(clean_domain),
            URLFeatureExtractor.count_suspicious_words(clean_url),
            URLFeatureExtractor.calculate_entropy(clean_domain),
            URLFeatureExtractor.count_special_chars(clean_url)
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
        # We use clean domain so 'www.google.com' (2 dots) becomes 'google.com' (1 dot) -> 0 subdomains
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
