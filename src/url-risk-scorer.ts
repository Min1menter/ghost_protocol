export interface URLRiskResult {
  verdict: 'ALLOW' | 'WARN' | 'BLOCK';
  score: number;
  reasons: string[];
}

export class URLRiskScorer {
  private personalTrustedList: Set<string>;
  private globalWhitelist: Set<string>;

  constructor() {
    this.personalTrustedList = new Set();
    this.globalWhitelist = new Set([
      'google.com',
      'github.com',
      'microsoft.com',
      'apple.com',
      'amazon.com',
      'facebook.com',
      'twitter.com',
      'linkedin.com',
      'youtube.com',
      'wikipedia.org',
      'stackoverflow.com',
      'reddit.com'
    ]);
  }

  addToPersonalTrustedList(url: string): void {
    const domain = this.extractDomain(url);
    if (domain) {
      this.personalTrustedList.add(domain);
    }
  }

  private extractDomain(url: string): string | null {
    try {
      const urlObj = new URL(url);
      return urlObj.hostname.toLowerCase();
    } catch {
      // Try to extract domain from string if URL parsing fails
      const domainMatch = url.match(/^https?:\/\/([^\/]+)/);
      return domainMatch ? domainMatch[1].toLowerCase() : null;
    }
  }

  private isIPAddress(domain: string): boolean {
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    return ipRegex.test(domain);
  }

  private getDomainAge(domain: string): number {
    // Mock implementation - in real scenario, this would use WHOIS API
    // For testing purposes, we'll simulate domain ages
    const mockAges: Record<string, number> = {
      'suspicious.xyz': 7,
      'newsite.top': 5,
      'malicious.tk': 3,
      'legitimate.dev': 10,
      'coolapp.io': 8
    };
    return mockAges[domain] || 30; // Default to 30 days if not in mock data
  }

  private isDeveloperSite(domain: string): boolean {
    const developerTlds = ['.dev', '.io'];
    return developerTlds.some(tld => domain.endsWith(tld));
  }

  scoreURL(url: string): URLRiskResult {
    const domain = this.extractDomain(url);
    
    if (!domain) {
      return {
        verdict: 'BLOCK',
        score: 100,
        reasons: ['Invalid URL format']
      };
    }

    // Phase 1: The Instant Check
    if (this.personalTrustedList.has(domain)) {
      return {
        verdict: 'ALLOW',
        score: 0,
        reasons: ['In personal trusted list']
      };
    }

    if (this.globalWhitelist.has(domain)) {
      return {
        verdict: 'ALLOW',
        score: 0,
        reasons: ['In global whitelist']
      };
    }

    // Phase 2: The Score Calculation
    let score = 0;
    const reasons: string[] = [];

    // Check file extensions
    const dangerousExtensions = ['.zip', '.mov', '.exe'];
    if (dangerousExtensions.some(ext => url.toLowerCase().endsWith(ext))) {
      score += 30;
      reasons.push('Dangerous file extension');
    }

    // Check suspicious TLDs
    const suspiciousTlds = ['.xyz', '.top', '.tk'];
    if (suspiciousTlds.some(tld => domain.endsWith(tld))) {
      score += 15;
      reasons.push('Suspicious top-level domain');
    }

    // Check for @ symbol (phishing attempt)
    if (url.includes('@')) {
      score += 50;
      reasons.push('Contains @ symbol (phishing attempt)');
    }

    // Check if it's an IP address
    if (this.isIPAddress(domain)) {
      score += 20;
      reasons.push('IP address instead of domain');
    }

    // Check for brand impersonation
    const suspiciousBrands = ['paypal', 'google', 'bank'];
    const urlLower = url.toLowerCase();
    if (suspiciousBrands.some(brand => urlLower.includes(brand))) {
      score += 40;
      reasons.push('Brand impersonation detected');
    }

    // Check domain age (only if not a developer site)
    if (!this.isDeveloperSite(domain)) {
      const domainAge = this.getDomainAge(domain);
      if (domainAge < 14) {
        score += 25;
        reasons.push('New domain (less than 14 days)');
      }
    }

    // Phase 3: The Verdict
    let verdict: 'ALLOW' | 'WARN' | 'BLOCK';
    if (score >= 50) {
      verdict = 'BLOCK';
    } else if (score >= 20) {
      verdict = 'WARN';
    } else {
      verdict = 'ALLOW';
    }

    return {
      verdict,
      score,
      reasons: reasons.length > 0 ? reasons : ['No suspicious patterns detected']
    };
  }

  // Phase 4: The Feedback
  unblockURL(url: string): void {
    this.addToPersonalTrustedList(url);
  }
}
