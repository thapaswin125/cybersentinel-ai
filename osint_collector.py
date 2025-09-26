"""
CyberSentinel AI - OSINT Intelligence Collector
Automated Open Source Intelligence gathering and analysis
"""

import requests
import asyncio
import aiohttp
from bs4 import BeautifulSoup
import json
import hashlib
from datetime import datetime, timedelta
import logging
import re
from urllib.parse import urljoin, urlparse
import time

class OSINTCollector:
    """
    Advanced OSINT collection engine for automated threat intelligence gathering
    """

    def __init__(self, config_path=None):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })

        self.threat_intel_feeds = [
            'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
            'https://sslbl.abuse.ch/blacklist/sslipblacklist.txt',
            'https://urlhaus.abuse.ch/downloads/text/',
        ]

        self.social_media_endpoints = {
            'twitter': 'https://api.twitter.com/2/tweets/search/recent',
            'reddit': 'https://www.reddit.com/r/cybersecurity/search.json'
        }

        # Configure logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

        # Threat keywords for monitoring
        self.threat_keywords = [
            'apt', 'malware', 'ransomware', 'phishing', 'data breach',
            'vulnerability', 'exploit', 'botnet', 'ddos', 'cyber attack'
        ]

    def collect_threat_feeds(self):
        """
        Collect indicators from public threat intelligence feeds
        """
        collected_indicators = []

        try:
            for feed_url in self.threat_intel_feeds:
                self.logger.info(f"Collecting from feed: {feed_url}")

                try:
                    response = self.session.get(feed_url, timeout=30)
                    if response.status_code == 200:
                        indicators = self.parse_feed_content(response.text, feed_url)
                        collected_indicators.extend(indicators)

                except Exception as e:
                    self.logger.error(f"Error collecting from {feed_url}: {e}")

                # Rate limiting
                time.sleep(2)

        except Exception as e:
            self.logger.error(f"Error in threat feed collection: {e}")

        return collected_indicators

    def parse_feed_content(self, content, source_url):
        """
        Parse threat intelligence feed content
        """
        indicators = []

        try:
            lines = content.strip().split('\n')

            for line in lines:
                line = line.strip()

                # Skip comments and empty lines
                if line.startswith('#') or not line:
                    continue

                # Detect indicator type
                indicator_type = self.detect_indicator_type(line)

                if indicator_type:
                    indicator = {
                        'value': line,
                        'type': indicator_type,
                        'source': source_url,
                        'collected_at': datetime.now().isoformat(),
                        'confidence': self.calculate_feed_confidence(source_url),
                        'tags': self.extract_tags_from_source(source_url)
                    }
                    indicators.append(indicator)

        except Exception as e:
            self.logger.error(f"Error parsing feed content: {e}")

        return indicators

    def detect_indicator_type(self, indicator):
        """
        Detect the type of indicator (IP, domain, URL, hash, etc.)
        """
        # IP address pattern
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'

        # Domain pattern
        domain_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}$'

        # URL pattern
        url_pattern = r'^https?://.*'

        # Hash patterns
        md5_pattern = r'^[a-fA-F0-9]{32}$'
        sha1_pattern = r'^[a-fA-F0-9]{40}$'
        sha256_pattern = r'^[a-fA-F0-9]{64}$'

        if re.match(ip_pattern, indicator):
            return 'ip'
        elif re.match(url_pattern, indicator):
            return 'url'
        elif re.match(domain_pattern, indicator):
            return 'domain'
        elif re.match(sha256_pattern, indicator):
            return 'sha256'
        elif re.match(sha1_pattern, indicator):
            return 'sha1'
        elif re.match(md5_pattern, indicator):
            return 'md5'

        return None

    def calculate_feed_confidence(self, source_url):
        """
        Calculate confidence score based on source reputation
        """
        trusted_sources = {
            'abuse.ch': 0.9,
            'virustotal.com': 0.85,
            'malwaredomainlist.com': 0.8,
            'phishtank.com': 0.8
        }

        for source, confidence in trusted_sources.items():
            if source in source_url:
                return confidence

        return 0.5  # Default confidence for unknown sources

    def extract_tags_from_source(self, source_url):
        """
        Extract relevant tags based on source URL
        """
        tags = []

        if 'feodo' in source_url:
            tags.extend(['botnet', 'banking-trojan'])
        elif 'sslbl' in source_url:
            tags.extend(['malware', 'c2-communication'])
        elif 'urlhaus' in source_url:
            tags.extend(['malware-hosting', 'payload-delivery'])

        return tags

    async def monitor_social_media(self, keywords=None):
        """
        Monitor social media platforms for threat-related discussions
        """
        if keywords is None:
            keywords = self.threat_keywords

        social_indicators = []

        try:
            # Monitor Reddit cybersecurity discussions
            reddit_data = await self.collect_reddit_intelligence(keywords)
            social_indicators.extend(reddit_data)

            # Note: Twitter API requires authentication
            # twitter_data = await self.collect_twitter_intelligence(keywords)
            # social_indicators.extend(twitter_data)

        except Exception as e:
            self.logger.error(f"Error monitoring social media: {e}")

        return social_indicators

    async def collect_reddit_intelligence(self, keywords):
        """
        Collect threat intelligence from Reddit cybersecurity communities
        """
        indicators = []

        try:
            async with aiohttp.ClientSession() as session:
                for keyword in keywords:
                    url = f"https://www.reddit.com/r/cybersecurity/search.json?q={keyword}&sort=new&limit=25"

                    try:
                        async with session.get(url) as response:
                            if response.status == 200:
                                data = await response.json()
                                posts = data.get('data', {}).get('children', [])

                                for post in posts:
                                    post_data = post.get('data', {})

                                    # Extract IOCs from post content
                                    iocs = self.extract_iocs_from_text(
                                        post_data.get('title', '') + ' ' + 
                                        post_data.get('selftext', '')
                                    )

                                    for ioc in iocs:
                                        indicator = {
                                            'value': ioc['value'],
                                            'type': ioc['type'],
                                            'source': 'Reddit r/cybersecurity',
                                            'source_url': f"https://reddit.com{post_data.get('permalink', '')}",
                                            'collected_at': datetime.now().isoformat(),
                                            'confidence': 0.6,  # Medium confidence for social media
                                            'context': post_data.get('title', ''),
                                            'tags': ['social-media', 'community-report', keyword]
                                        }
                                        indicators.append(indicator)

                    except Exception as e:
                        self.logger.error(f"Error collecting Reddit data for {keyword}: {e}")

                    # Rate limiting
                    await asyncio.sleep(2)

        except Exception as e:
            self.logger.error(f"Error in Reddit intelligence collection: {e}")

        return indicators

    def extract_iocs_from_text(self, text):
        """
        Extract Indicators of Compromise from text content
        """
        iocs = []

        # IP address pattern
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'

        # Domain pattern
        domain_pattern = r'\b[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}\b'

        # URL pattern
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'

        # Hash patterns
        hash_patterns = {
            'md5': r'\b[a-fA-F0-9]{32}\b',
            'sha1': r'\b[a-fA-F0-9]{40}\b',
            'sha256': r'\b[a-fA-F0-9]{64}\b'
        }

        # Extract IPs
        ips = re.findall(ip_pattern, text)
        for ip in ips:
            iocs.append({'value': ip, 'type': 'ip'})

        # Extract URLs
        urls = re.findall(url_pattern, text)
        for url in urls:
            iocs.append({'value': url, 'type': 'url'})

        # Extract domains (excluding IPs and URLs)
        domains = re.findall(domain_pattern, text)
        for domain in domains:
            if not re.match(ip_pattern, domain) and not any(url.startswith('http') for url in urls if domain in url):
                iocs.append({'value': domain, 'type': 'domain'})

        # Extract hashes
        for hash_type, pattern in hash_patterns.items():
            hashes = re.findall(pattern, text)
            for hash_val in hashes:
                iocs.append({'value': hash_val, 'type': hash_type})

        return iocs

    def enrich_indicators(self, indicators):
        """
        Enrich collected indicators with additional context
        """
        enriched_indicators = []

        for indicator in indicators:
            try:
                enriched = indicator.copy()

                # Add geolocation for IP addresses
                if indicator['type'] == 'ip':
                    geo_info = self.get_ip_geolocation(indicator['value'])
                    enriched['geolocation'] = geo_info

                # Add reputation scores
                enriched['reputation_score'] = self.calculate_reputation_score(indicator)

                # Add threat categories
                enriched['threat_categories'] = self.categorize_threat(indicator)

                enriched_indicators.append(enriched)

            except Exception as e:
                self.logger.error(f"Error enriching indicator {indicator['value']}: {e}")
                enriched_indicators.append(indicator)

        return enriched_indicators

    def get_ip_geolocation(self, ip_address):
        """
        Get geolocation information for IP address (mock implementation)
        """
        # In a real implementation, you would use a geolocation API
        mock_geo = {
            'country': 'Unknown',
            'city': 'Unknown',
            'latitude': 0.0,
            'longitude': 0.0,
            'asn': 'Unknown'
        }

        return mock_geo

    def calculate_reputation_score(self, indicator):
        """
        Calculate reputation score for indicator
        """
        base_score = 0.5

        # Adjust based on source confidence
        source_confidence = indicator.get('confidence', 0.5)

        # Adjust based on tags
        threat_tags = ['malware', 'botnet', 'phishing', 'c2-communication']
        tag_score = sum(0.1 for tag in indicator.get('tags', []) if tag in threat_tags)

        reputation_score = min(1.0, base_score + source_confidence + tag_score)
        return reputation_score

    def categorize_threat(self, indicator):
        """
        Categorize threat based on indicator characteristics
        """
        categories = []

        tags = indicator.get('tags', [])
        source = indicator.get('source', '').lower()

        if any(tag in ['malware', 'trojan', 'virus'] for tag in tags):
            categories.append('Malware')
        if any(tag in ['botnet', 'c2-communication'] for tag in tags):
            categories.append('Botnet')
        if any(tag in ['phishing', 'credential-harvesting'] for tag in tags):
            categories.append('Phishing')
        if 'ddos' in source or 'ddos' in tags:
            categories.append('DDoS')

        return categories if categories else ['Unknown']

    def generate_report(self, indicators):
        """
        Generate OSINT intelligence report
        """
        report = {
            'generated_at': datetime.now().isoformat(),
            'total_indicators': len(indicators),
            'indicator_types': {},
            'threat_categories': {},
            'top_sources': {},
            'indicators': indicators[:100]  # Limit to first 100 for report
        }

        # Count indicator types
        for indicator in indicators:
            ioc_type = indicator.get('type', 'unknown')
            report['indicator_types'][ioc_type] = report['indicator_types'].get(ioc_type, 0) + 1

        # Count threat categories
        for indicator in indicators:
            categories = indicator.get('threat_categories', ['Unknown'])
            for category in categories:
                report['threat_categories'][category] = report['threat_categories'].get(category, 0) + 1

        # Count top sources
        for indicator in indicators:
            source = indicator.get('source', 'Unknown')
            report['top_sources'][source] = report['top_sources'].get(source, 0) + 1

        return report

# Example usage
if __name__ == "__main__":
    async def main():
        collector = OSINTCollector()

        print("=== CyberSentinel AI OSINT Collection ===\n")

        # Collect from threat intelligence feeds
        print("Collecting from threat intelligence feeds...")
        feed_indicators = collector.collect_threat_feeds()
        print(f"Collected {len(feed_indicators)} indicators from feeds")

        # Monitor social media (limited example)
        print("\nMonitoring social media...")
        social_indicators = await collector.monitor_social_media(['malware', 'phishing'])
        print(f"Collected {len(social_indicators)} indicators from social media")

        # Combine all indicators
        all_indicators = feed_indicators + social_indicators

        # Enrich indicators
        print("\nEnriching indicators...")
        enriched_indicators = collector.enrich_indicators(all_indicators)

        # Generate report
        report = collector.generate_report(enriched_indicators)

        print("\n=== OSINT Intelligence Report ===")
        print(f"Total Indicators: {report['total_indicators']}")
        print(f"Indicator Types: {report['indicator_types']}")
        print(f"Threat Categories: {report['threat_categories']}")
        print(f"Top Sources: {list(report['top_sources'].keys())[:5]}")

        # Save report
        with open('osint_report.json', 'w') as f:
            json.dump(report, f, indent=2)

        print("\nReport saved to osint_report.json")

    # Run the async main function
    asyncio.run(main())
