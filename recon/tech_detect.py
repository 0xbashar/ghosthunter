"""
TechDetector — Fingerprinting web technologies.
Analyzes HTTP headers, cookies, and HTML content to identify:
  - Languages (PHP, Python, Java, Ruby, Node.js)
  - Frameworks (Django, Spring, Rails, Express, Laravel)
  - Frontend (React, Vue, Angular)
  - CMS (WordPress, Drupal)
  - Servers (Nginx, Apache, IIS)
"""
from __future__ import annotations
import asyncio
from typing import Dict
from core.logger import Logger

log = Logger.get_logger("recon_tech")

# Signature database (simplified for example)
SIGNATURES = {
    "languages": {
        "PHP": ["X-Powered-By: PHP", ".php", "PHPSESSID"],
        "Python": ["X-Powered-By: Python", "WSGI", "csrftoken"],
        "Java": ["JSESSIONID", "X-Powered-By: Servlet", "Set-Cookie: JSESSIONID"],
        "Ruby": ["X-Powered-By: Phusion Passenger", "Rails", "_session_id"],
        "Node.js": ["X-Powered-By: Express", "Connect.sid", "X-Powered-By: Next"]
    },
    "frameworks": {
        "Django": ["csrftoken", "X-Frame-Options: DENY", "django"],
        "Spring Boot": ["X-Application-Context", "Spring", "actuator"],
        "Ruby on Rails": ["X-Rack-Cache", "Rails", "X-Runtime"],
        "Laravel": ["laravel_session", "XSRF-TOKEN", "Laravel"],
        "Express": ["X-Powered-By: Express", "ETag: W/"]
    },
    "frontend": {
        "React": ["react", "__NEXT_DATA__", "react-dom"],
        "Vue.js": ["vue", "__vue__", "vue.runtime"],
        "Angular": ["ng-app", "angular", "ng-version"]
    },
    "cms": {
        "WordPress": ["wp-content", "wp-includes", "X-Pingback"],
        "Drupal": ["X-Generator: Drupal", "drupal.js", "Drupal.settings"],
        "Joomla": ["X-Content-Powered-By: Joomla", "joomla"]
    },
    "servers": {
        "Nginx": ["Server: nginx"],
        "Apache": ["Server: Apache"],
        "IIS": ["Server: Microsoft-IIS"],
        "Cloudflare": ["Server: cloudflare", "cf-ray"]
    }
}

class TechDetector:
    def __init__(self, http):
        self.http = http

    async def detect(self, target: str) -> Dict[str, str]:
        log.info(f"Fingerprinting technology stack for {target}")
        stack = {}
        
        r = await self.http.arequest("GET", target)
        if not r:
            return stack
            
        headers = str(r.headers).lower()
        body = (r.text or "")[:5000].lower()
        cookies = r.headers.get("Set-Cookie", "").lower()
        
        # Check all signatures
        for category, techs in SIGNATURES.items():
            for tech, sigs in techs.items():
                if any(sig.lower() in headers or sig.lower() in body or sig.lower() in cookies for sig in sigs):
                    stack[category] = tech
                    log.debug(f"Detected {tech} ({category})")
                    break
                    
        # Special check for Spring Boot Actuator (High-Value Target)
        if "/actuator" in body or "X-Application-Context" in headers:
            stack["framework"] = "Spring Boot"
            stack["high_value_target"] = "Spring Boot Actuator Detected"
            
        log.success(f"Stack: {stack}")
        return stack
