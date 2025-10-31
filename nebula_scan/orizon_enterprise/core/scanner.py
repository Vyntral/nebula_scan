"""
Advanced Enterprise Scanner Core
Enhanced subdomain enumeration with enterprise features
"""
import asyncio
import aiohttp
import aiodns
import socket
import ssl
import ipaddress
import re
import time
import logging
from typing import List, Dict, Set, Optional, Any
from datetime import datetime
from urllib.parse import urlparse
import json

from config.settings import settings

logger = logging.getLogger(__name__)


class EnterpriseScanner:
    """
    Enterprise-grade scanner with advanced capabilities
    """

    def __init__(
        self,
        domain: str,
        wordlist: Optional[List[str]] = None,
        config: Optional[Dict[str, Any]] = None
    ):
        self.domain = domain
        self.config = config or {}
        self.subdomains: Dict[str, Dict] = {}
        self.resolver = aiodns.DNSResolver()

        # Semaphores for rate limiting
        self.dns_semaphore = asyncio.Semaphore(settings.scanning.max_concurrent_scans)
        self.http_semaphore = asyncio.Semaphore(50)
        self.port_semaphore = asyncio.Semaphore(100)

        # Wordlist
        self.wordlist = wordlist if wordlist else self._load_default_wordlist()

        # API keys
        self.api_keys = {
            'virustotal': settings.api_keys.virustotal_api_key,
            'securitytrails': settings.api_keys.securitytrails_api_key,
            'censys_id': settings.api_keys.censys_id,
            'censys_secret': settings.api_keys.censys_secret,
            'shodan': settings.api_keys.shodan_api_key,
        }

        # Statistics
        self.stats = {
            'total_subdomains': 0,
            'active_subdomains': 0,
            'passive_sources': 0,
            'bruteforce_found': 0,
            'total_ips': 0,
            'technologies_detected': 0,
            'vulnerabilities_found': 0,
            'emails_found': 0,
        }

        # Progress tracking
        self.progress = 0.0
        self.total_tasks = 0
        self.completed_tasks = 0

        # Session
        self.session: Optional[aiohttp.ClientSession] = None

    def _load_default_wordlist(self) -> List[str]:
        """Load default subdomain wordlist"""
        return [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'vpn', 'mx', 'mx1', 'mx2',
            'shop', 'forum', 'blog', 'dev', 'staging', 'api', 'app', 'mobile', 'admin',
            'test', 'demo', 'beta', 'alpha', 'portal', 'secure', 'remote', 'cloud', 'cdn',
            'ftp2', 'backup', 'news', 'img', 'images', 'video', 'static', 'docs', 'doc',
            'help', 'support', 'chat', 'beta', 'alpha', 'staging', 'prod', 'production',
            'git', 'svn', 'jenkins', 'jira', 'confluence', 'wiki', 'redmine', 'gitlab',
            'monitor', 'monitoring', 'grafana', 'prometheus', 'kibana', 'elastic', 'logstash',
            'vpn', 'ssl', 'owa', 'exchange', 'office', 'outlook', 'teams', 'sharepoint',
            'crm', 'erp', 'hr', 'finance', 'accounting', 'invoices', 'billing', 'payments',
            'db', 'database', 'mysql', 'postgres', 'oracle', 'mssql', 'redis', 'mongo',
            'api-v1', 'api-v2', 'api-v3', 'api-dev', 'api-staging', 'api-prod',
            'app-dev', 'app-staging', 'app-prod', 'web-dev', 'web-staging', 'web-prod',
            'mail1', 'mail2', 'mail3', 'smtp1', 'smtp2', 'pop3', 'imap',
            'store', 'shop', 'cart', 'checkout', 'payment', 'order', 'orders',
            'legacy', 'old', 'archive', 'backup', 'bak', 'temp', 'tmp',
            'assets', 'cdn1', 'cdn2', 'media', 'files', 'downloads', 'upload', 'uploads'
        ]

    async def run(self, callback=None) -> Dict[str, Any]:
        """
        Run complete scan with all modules

        Args:
            callback: Optional callback function for progress updates

        Returns:
            Dict with scan results
        """
        start_time = time.time()
        logger.info(f"Starting enterprise scan for {self.domain}")

        # Create aiohttp session
        timeout = aiohttp.ClientTimeout(total=settings.scanning.http_timeout)
        connector = aiohttp.TCPConnector(limit=100, limit_per_host=10)
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers={'User-Agent': settings.scanning.user_agent}
        )

        try:
            # Phase 1: Subdomain Enumeration
            logger.info("Phase 1: Subdomain Enumeration")
            await self._enumerate_subdomains(callback)

            # Phase 2: DNS Resolution & IP Discovery
            logger.info("Phase 2: DNS Resolution")
            await self._resolve_subdomains(callback)

            # Phase 3: HTTP/HTTPS Discovery
            logger.info("Phase 3: HTTP/HTTPS Discovery")
            await self._http_discovery(callback)

            # Phase 4: Port Scanning
            logger.info("Phase 4: Port Scanning")
            if settings.scanning.common_ports:
                await self._port_scanning(callback)

            # Phase 5: Technology Detection
            logger.info("Phase 5: Technology Detection")
            if settings.scanning.enable_tech_detection:
                await self._technology_detection(callback)

            # Phase 6: WAF Detection
            logger.info("Phase 6: WAF Detection")
            if settings.scanning.enable_waf_detection:
                await self._waf_detection(callback)

            # Phase 7: SSL/TLS Analysis
            logger.info("Phase 7: SSL/TLS Analysis")
            if settings.scanning.enable_ssl_analysis:
                await self._ssl_analysis(callback)

            # Phase 8: Vulnerability Scanning
            logger.info("Phase 8: Vulnerability Scanning")
            if settings.scanning.enable_vulnerability_scan:
                await self._vulnerability_scan(callback)

            # Phase 9: Email Enumeration
            logger.info("Phase 9: Email Enumeration")
            await self._email_enumeration(callback)

            # Calculate final statistics
            duration = time.time() - start_time
            self._calculate_statistics()

            results = {
                'domain': self.domain,
                'scan_date': datetime.utcnow().isoformat(),
                'duration_seconds': round(duration, 2),
                'subdomains': self.subdomains,
                'statistics': self.stats,
                'config': self.config
            }

            logger.info(f"Scan completed in {duration:.2f}s - Found {self.stats['total_subdomains']} subdomains")
            return results

        finally:
            await self.session.close()

    async def _enumerate_subdomains(self, callback=None):
        """Enumerate subdomains using passive and active methods"""
        found = set()

        # Passive enumeration from multiple sources
        passive_tasks = [
            self._crtsh_enumeration(),
            self._virustotal_enumeration(),
            self._alienvault_enumeration(),
            self._threatcrowd_enumeration(),
            self._hackertarget_enumeration(),
        ]

        # Add API-based sources if keys are available
        if self.api_keys.get('securitytrails'):
            passive_tasks.append(self._securitytrails_enumeration())

        if self.api_keys.get('censys_id') and self.api_keys.get('censys_secret'):
            passive_tasks.append(self._censys_enumeration())

        if self.api_keys.get('shodan'):
            passive_tasks.append(self._shodan_enumeration())

        # Execute all passive enumeration tasks
        passive_results = await asyncio.gather(*passive_tasks, return_exceptions=True)

        for result in passive_results:
            if isinstance(result, set):
                found.update(result)
                self.stats['passive_sources'] += 1

        # Active bruteforce enumeration
        bruteforce_found = await self._bruteforce_enumeration()
        found.update(bruteforce_found)

        # Store all found subdomains
        for subdomain in found:
            if subdomain not in self.subdomains:
                self.subdomains[subdomain] = {
                    'subdomain': subdomain,
                    'discovered_at': datetime.utcnow().isoformat(),
                    'ips': [],
                    'is_active': False,
                }

        self.stats['total_subdomains'] = len(self.subdomains)
        logger.info(f"Found {len(found)} unique subdomains")

    async def _crtsh_enumeration(self) -> Set[str]:
        """Certificate Transparency Logs enumeration"""
        found = set()
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"

        try:
            async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as response:
                if response.status == 200:
                    data = await response.json()
                    for entry in data:
                        name = entry.get('name_value', '')
                        # Handle wildcard and multiple domains
                        for subdomain in name.split('\n'):
                            subdomain = subdomain.strip().replace('*.', '')
                            if subdomain.endswith(self.domain):
                                found.add(subdomain)
                    logger.debug(f"crt.sh: Found {len(found)} subdomains")
        except Exception as e:
            logger.warning(f"crt.sh enumeration failed: {e}")

        return found

    async def _virustotal_enumeration(self) -> Set[str]:
        """VirusTotal API enumeration"""
        found = set()
        if not self.api_keys.get('virustotal'):
            return found

        url = f"https://www.virustotal.com/api/v3/domains/{self.domain}/subdomains"
        headers = {"x-apikey": self.api_keys['virustotal']}

        try:
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    for item in data.get('data', []):
                        subdomain = item.get('id', '')
                        if subdomain:
                            found.add(subdomain)
                    logger.debug(f"VirusTotal: Found {len(found)} subdomains")
        except Exception as e:
            logger.warning(f"VirusTotal enumeration failed: {e}")

        return found

    async def _alienvault_enumeration(self) -> Set[str]:
        """AlienVault OTX enumeration"""
        found = set()
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"

        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    for entry in data.get('passive_dns', []):
                        hostname = entry.get('hostname', '')
                        if hostname.endswith(self.domain):
                            found.add(hostname)
                    logger.debug(f"AlienVault: Found {len(found)} subdomains")
        except Exception as e:
            logger.warning(f"AlienVault enumeration failed: {e}")

        return found

    async def _threatcrowd_enumeration(self) -> Set[str]:
        """ThreatCrowd enumeration"""
        found = set()
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}"

        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    for subdomain in data.get('subdomains', []):
                        found.add(subdomain)
                    logger.debug(f"ThreatCrowd: Found {len(found)} subdomains")
        except Exception as e:
            logger.warning(f"ThreatCrowd enumeration failed: {e}")

        return found

    async def _hackertarget_enumeration(self) -> Set[str]:
        """HackerTarget enumeration"""
        found = set()
        url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"

        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    text = await response.text()
                    for line in text.split('\n'):
                        if ',' in line:
                            subdomain = line.split(',')[0].strip()
                            if subdomain.endswith(self.domain):
                                found.add(subdomain)
                    logger.debug(f"HackerTarget: Found {len(found)} subdomains")
        except Exception as e:
            logger.warning(f"HackerTarget enumeration failed: {e}")

        return found

    async def _securitytrails_enumeration(self) -> Set[str]:
        """SecurityTrails API enumeration"""
        found = set()
        if not self.api_keys.get('securitytrails'):
            return found

        url = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains"
        headers = {"APIKEY": self.api_keys['securitytrails']}

        try:
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    for subdomain in data.get('subdomains', []):
                        found.add(f"{subdomain}.{self.domain}")
                    logger.debug(f"SecurityTrails: Found {len(found)} subdomains")
        except Exception as e:
            logger.warning(f"SecurityTrails enumeration failed: {e}")

        return found

    async def _censys_enumeration(self) -> Set[str]:
        """Censys API enumeration"""
        found = set()
        if not (self.api_keys.get('censys_id') and self.api_keys.get('censys_secret')):
            return found

        url = f"https://search.censys.io/api/v2/certificates/search"
        auth = aiohttp.BasicAuth(self.api_keys['censys_id'], self.api_keys['censys_secret'])
        params = {"q": self.domain}

        try:
            async with self.session.get(url, auth=auth, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    for hit in data.get('result', {}).get('hits', []):
                        names = hit.get('names', [])
                        for name in names:
                            if name.endswith(self.domain):
                                found.add(name.replace('*.', ''))
                    logger.debug(f"Censys: Found {len(found)} subdomains")
        except Exception as e:
            logger.warning(f"Censys enumeration failed: {e}")

        return found

    async def _shodan_enumeration(self) -> Set[str]:
        """Shodan API enumeration"""
        found = set()
        if not self.api_keys.get('shodan'):
            return found

        url = f"https://api.shodan.io/dns/domain/{self.domain}"
        params = {"key": self.api_keys['shodan']}

        try:
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    for subdomain in data.get('subdomains', []):
                        found.add(f"{subdomain}.{self.domain}")
                    logger.debug(f"Shodan: Found {len(found)} subdomains")
        except Exception as e:
            logger.warning(f"Shodan enumeration failed: {e}")

        return found

    async def _bruteforce_enumeration(self) -> Set[str]:
        """Bruteforce subdomain enumeration using wordlist"""
        found = set()
        tasks = []

        for word in self.wordlist:
            subdomain = f"{word}.{self.domain}"
            tasks.append(self._check_subdomain_dns(subdomain))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for subdomain, exists in zip([f"{w}.{self.domain}" for w in self.wordlist], results):
            if exists and not isinstance(exists, Exception):
                found.add(subdomain)

        self.stats['bruteforce_found'] = len(found)
        logger.debug(f"Bruteforce: Found {len(found)} subdomains")
        return found

    async def _check_subdomain_dns(self, subdomain: str) -> bool:
        """Check if subdomain exists via DNS"""
        async with self.dns_semaphore:
            try:
                await self.resolver.query(subdomain, 'A')
                return True
            except:
                return False

    async def _resolve_subdomains(self, callback=None):
        """Resolve IP addresses for all subdomains"""
        tasks = []
        for subdomain in self.subdomains.keys():
            tasks.append(self._resolve_subdomain(subdomain))

        await asyncio.gather(*tasks, return_exceptions=True)

    async def _resolve_subdomain(self, subdomain: str):
        """Resolve single subdomain to IP addresses"""
        async with self.dns_semaphore:
            try:
                result = await self.resolver.query(subdomain, 'A')
                ips = [r.host for r in result]
                self.subdomains[subdomain]['ips'] = ips
                self.subdomains[subdomain]['is_active'] = True
                self.stats['active_subdomains'] += 1

                # Check if internal IP
                for ip in ips:
                    try:
                        ip_obj = ipaddress.ip_address(ip)
                        self.subdomains[subdomain]['is_internal'] = ip_obj.is_private
                        break
                    except:
                        pass

            except Exception as e:
                logger.debug(f"Failed to resolve {subdomain}: {e}")

    async def _http_discovery(self, callback=None):
        """Discover HTTP/HTTPS services"""
        tasks = []
        for subdomain, data in self.subdomains.items():
            if data.get('is_active'):
                tasks.append(self._check_http(subdomain))

        await asyncio.gather(*tasks, return_exceptions=True)

    async def _check_http(self, subdomain: str):
        """Check HTTP/HTTPS availability and get basic info"""
        async with self.http_semaphore:
            for scheme in ['https', 'http']:
                url = f"{scheme}://{subdomain}"
                try:
                    start = time.time()
                    async with self.session.get(url, allow_redirects=True, ssl=False) as response:
                        response_time = (time.time() - start) * 1000

                        self.subdomains[subdomain][f'{scheme}_status'] = response.status
                        self.subdomains[subdomain]['response_time_ms'] = round(response_time, 2)
                        self.subdomains[subdomain]['server'] = response.headers.get('Server', '')

                        # Get page title
                        if response.status == 200:
                            try:
                                html = await response.text()
                                title_match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
                                if title_match:
                                    self.subdomains[subdomain]['title'] = title_match.group(1)[:200]
                            except:
                                pass

                        break  # If HTTPS works, don't check HTTP

                except Exception as e:
                    logger.debug(f"HTTP check failed for {url}: {e}")

    async def _port_scanning(self, callback=None):
        """Scan common ports on active subdomains"""
        tasks = []
        for subdomain, data in self.subdomains.items():
            if data.get('ips'):
                for ip in data['ips'][:1]:  # Scan only first IP
                    tasks.append(self._scan_ports(subdomain, ip))

        await asyncio.gather(*tasks, return_exceptions=True)

    async def _scan_ports(self, subdomain: str, ip: str):
        """Scan ports for a subdomain"""
        open_ports = []

        for port in settings.scanning.common_ports:
            if await self._check_port(ip, port):
                open_ports.append(port)

        if open_ports:
            self.subdomains[subdomain]['open_ports'] = open_ports

    async def _check_port(self, ip: str, port: int) -> bool:
        """Check if a port is open"""
        async with self.port_semaphore:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=settings.scanning.port_scan_timeout
                )
                writer.close()
                await writer.wait_closed()
                return True
            except:
                return False

    async def _technology_detection(self, callback=None):
        """Detect technologies used by websites"""
        # Implementation would use wappalyzer or similar
        # For now, basic header-based detection
        for subdomain, data in self.subdomains.items():
            if data.get('https_status') == 200 or data.get('http_status') == 200:
                technologies = []

                server = data.get('server', '')
                if 'nginx' in server.lower():
                    technologies.append('Nginx')
                elif 'apache' in server.lower():
                    technologies.append('Apache')
                elif 'cloudflare' in server.lower():
                    technologies.append('Cloudflare')

                if technologies:
                    self.subdomains[subdomain]['technologies'] = technologies
                    self.stats['technologies_detected'] += len(technologies)

    async def _waf_detection(self, callback=None):
        """Detect Web Application Firewalls"""
        # Basic WAF detection based on headers and responses
        waf_signatures = {
            'Cloudflare': ['__cfduid', 'cf-ray'],
            'AWS WAF': ['x-amzn-trace-id', 'x-amzn-requestid'],
            'Akamai': ['akamai', 'x-akamai'],
            'Imperva': ['incap_ses', 'visid_incap'],
        }

        for subdomain, data in self.subdomains.items():
            if data.get('server'):
                for waf, signatures in waf_signatures.items():
                    if any(sig in data.get('server', '').lower() for sig in signatures):
                        self.subdomains[subdomain]['waf'] = waf
                        break

    async def _ssl_analysis(self, callback=None):
        """Analyze SSL/TLS certificates"""
        for subdomain, data in self.subdomains.items():
            if data.get('https_status'):
                try:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE

                    conn = await asyncio.wait_for(
                        asyncio.open_connection(subdomain, 443, ssl=context),
                        timeout=5
                    )
                    reader, writer = conn

                    cert = writer.get_extra_info('ssl_object').getpeercert()
                    self.subdomains[subdomain]['ssl_info'] = {
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'valid_from': cert.get('notBefore'),
                        'valid_to': cert.get('notAfter'),
                    }

                    writer.close()
                    await writer.wait_closed()

                except Exception as e:
                    logger.debug(f"SSL analysis failed for {subdomain}: {e}")

    async def _vulnerability_scan(self, callback=None):
        """Basic vulnerability scanning"""
        # This would integrate with vulnerability scanners
        # For now, check for common misconfigurations
        for subdomain, data in self.subdomains.items():
            vulnerabilities = []

            # Check for missing security headers
            if not data.get('server'):
                continue

            # Example checks (expand this significantly in production)
            if data.get('https_status') and not data.get('ssl_info'):
                vulnerabilities.append({
                    'type': 'ssl_misconfiguration',
                    'severity': 'medium',
                    'description': 'SSL/TLS configuration issues detected'
                })

            if vulnerabilities:
                self.subdomains[subdomain]['vulnerabilities'] = vulnerabilities
                self.stats['vulnerabilities_found'] += len(vulnerabilities)

    async def _email_enumeration(self, callback=None):
        """Enumerate email addresses from web pages"""
        email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        found_emails = set()

        for subdomain, data in self.subdomains.items():
            if data.get('https_status') == 200 or data.get('http_status') == 200:
                scheme = 'https' if data.get('https_status') == 200 else 'http'
                url = f"{scheme}://{subdomain}"

                try:
                    async with self.session.get(url, ssl=False) as response:
                        if response.status == 200:
                            html = await response.text()
                            emails = email_pattern.findall(html)
                            if emails:
                                self.subdomains[subdomain]['emails'] = list(set(emails))
                                found_emails.update(emails)
                except Exception as e:
                    logger.debug(f"Email enumeration failed for {url}: {e}")

        self.stats['emails_found'] = len(found_emails)

    def _calculate_statistics(self):
        """Calculate final statistics"""
        total_ips = set()
        for data in self.subdomains.values():
            if data.get('ips'):
                total_ips.update(data['ips'])

        self.stats['total_ips'] = len(total_ips)
        self.stats['total_subdomains'] = len(self.subdomains)

        # Count active subdomains
        self.stats['active_subdomains'] = sum(
            1 for d in self.subdomains.values() if d.get('is_active')
        )
