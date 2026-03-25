import whois
from datetime import datetime, timezone
from urllib.parse import urlparse

class WhoisChecker:
    """Verifies domain ownership and registration age."""
    
    @staticmethod
    def get_domain_age(url):
        """Returns the domain age in days."""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc or url.split('/')[0]
            
            # Remove port if present
            domain = domain.split(':')[0]
                
            w = whois.whois(domain)
            
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if not creation_date:
                return -1
                
            # Normalize to UTC/Naive to avoid the offset error
            now = datetime.now()
            if creation_date.tzinfo is not None:
                now = datetime.now(timezone.utc)
            
            delta = now - creation_date
            return delta.days
        except Exception as e:
            print(f"WHOIS Error for {url}: {e}")
            return -1

    @staticmethod
    def is_trustworthy(url, min_days=365):
        age = WhoisChecker.get_domain_age(url)
        return age >= min_days
