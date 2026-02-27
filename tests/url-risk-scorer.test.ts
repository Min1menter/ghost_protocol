import { URLRiskScorer, URLRiskResult } from '../src/url-risk-scorer';

describe('URLRiskScorer', () => {
  let scorer: URLRiskScorer;

  beforeEach(() => {
    scorer = new URLRiskScorer();
  });

  describe('Phase 1: Instant Check', () => {
    test('should ALLOW URLs in personal trusted list', () => {
      scorer.addToPersonalTrustedList('https://trusted-site.com');
      const result = scorer.scoreURL('https://trusted-site.com/page');
      
      expect(result.verdict).toBe('ALLOW');
      expect(result.score).toBe(0);
      expect(result.reasons).toContain('In personal trusted list');
    });

    test('should ALLOW URLs in global whitelist', () => {
      const result = scorer.scoreURL('https://google.com/search');
      
      expect(result.verdict).toBe('ALLOW');
      expect(result.score).toBe(0);
      expect(result.reasons).toContain('In global whitelist');
    });

    test('should ALLOW GitHub URLs', () => {
      const result = scorer.scoreURL('https://github.com/user/repo');
      
      expect(result.verdict).toBe('ALLOW');
      expect(result.score).toBe(0);
      expect(result.reasons).toContain('In global whitelist');
    });
  });

  describe('Phase 2: Score Calculation', () => {
    test('should add 30 points for dangerous file extensions', () => {
      const testCases = [
        'https://example.com/file.zip',
        'https://example.com/video.mov',
        'https://example.com/program.exe'
      ];

      testCases.forEach(url => {
        const result = scorer.scoreURL(url);
        expect(result.score).toBeGreaterThanOrEqual(30);
        expect(result.reasons).toContain('Dangerous file extension');
      });
    });

    test('should add 15 points for suspicious TLDs', () => {
      const testCases = [
        'https://suspicious.xyz',
        'https://newsite.top',
        'https://malicious.tk'
      ];

      testCases.forEach(url => {
        const result = scorer.scoreURL(url);
        expect(result.score).toBeGreaterThanOrEqual(15);
        expect(result.reasons).toContain('Suspicious top-level domain');
      });
    });

    test('should add 50 points for @ symbol', () => {
      const url = 'https://example.com@malicious.com/phishing';
      const result = scorer.scoreURL(url);
      
      expect(result.score).toBeGreaterThanOrEqual(50);
      expect(result.reasons).toContain('Contains @ symbol (phishing attempt)');
    });

    test('should add 20 points for IP addresses', () => {
      const url = 'http://192.168.1.1/login';
      const result = scorer.scoreURL(url);
      
      expect(result.score).toBeGreaterThanOrEqual(20);
      expect(result.reasons).toContain('IP address instead of domain');
    });

    test('should add 40 points for brand impersonation', () => {
      const testCases = [
        'https://paypal-secure.com/login',
        'https://google-drive.com/files',
        'https://mybank-account.com'
      ];

      testCases.forEach(url => {
        const result = scorer.scoreURL(url);
        expect(result.score).toBeGreaterThanOrEqual(40);
        expect(result.reasons).toContain('Brand impersonation detected');
      });
    });

    test('should add 25 points for new domains (not developer sites)', () => {
      const url = 'https://suspicious.xyz';
      const result = scorer.scoreURL(url);
      
      expect(result.score).toBeGreaterThanOrEqual(40); // 15 for .xyz + 25 for new domain
      expect(result.reasons).toContain('New domain (less than 14 days)');
    });

    test('should NOT add domain age penalty for developer sites', () => {
      const url = 'https://legitimate.dev';
      const result = scorer.scoreURL(url);
      
      expect(result.reasons).not.toContain('New domain (less than 14 days)');
    });

    test('should accumulate multiple risk factors', () => {
      const url = 'https://paypal-secure.xyz@192.168.1.1/malware.exe';
      const result = scorer.scoreURL(url);
      
      expect(result.score).toBeGreaterThanOrEqual(140); // 30 + 15 + 50 + 20 + 40
      expect(result.reasons.length).toBeGreaterThan(3);
    });
  });

  describe('Phase 3: The Verdict', () => {
    test('should BLOCK URLs with score >= 50', () => {
      const url = 'https://example.com@malicious.com'; // 50 points for @ symbol
      const result = scorer.scoreURL(url);
      
      expect(result.verdict).toBe('BLOCK');
      expect(result.score).toBeGreaterThanOrEqual(50);
    });

    test('should WARN URLs with score 20-49', () => {
      const url = 'http://192.168.1.1'; // 20 points for IP address
      const result = scorer.scoreURL(url);
      
      expect(result.verdict).toBe('WARN');
      expect(result.score).toBeGreaterThanOrEqual(20);
      expect(result.score).toBeLessThan(50);
    });

    test('should ALLOW URLs with score 0-19', () => {
      const url = 'https://example.com';
      const result = scorer.scoreURL(url);
      
      expect(result.verdict).toBe('ALLOW');
      expect(result.score).toBeLessThan(20);
    });
  });

  describe('Phase 4: The Feedback', () => {
    test('should add URL to personal trusted list when unblocked', () => {
      const url = 'https://blocked-site.com';
      
      // Initially should be blocked/warned
      const initialResult = scorer.scoreURL(url);
      expect(initialResult.reasons).not.toContain('In personal trusted list');
      
      // Unblock the URL
      scorer.unblockURL(url);
      
      // Now should be allowed
      const unblockedResult = scorer.scoreURL(url);
      expect(unblockedResult.verdict).toBe('ALLOW');
      expect(unblockedResult.reasons).toContain('In personal trusted list');
    });
  });

  describe('Edge Cases', () => {
    test('should handle invalid URLs', () => {
      const result = scorer.scoreURL('not-a-valid-url');
      
      expect(result.verdict).toBe('BLOCK');
      expect(result.score).toBe(100);
      expect(result.reasons).toContain('Invalid URL format');
    });

    test('should handle URLs without protocol', () => {
      const result = scorer.scoreURL('example.com/page');
      
      expect(result.verdict).toBeDefined();
      expect(result.score).toBeGreaterThanOrEqual(0);
    });

    test('should be case insensitive', () => {
      const result1 = scorer.scoreURL('https://PAYPAL-SECure.com');
      const result2 = scorer.scoreURL('https://paypal-secure.com');
      
      expect(result1.score).toBe(result2.score);
      expect(result1.verdict).toBe(result2.verdict);
    });

    test('should handle complex URLs with multiple risk factors', () => {
      const url = 'https://paypal-secure.xyz@192.168.1.1/files/malware.exe';
      const result = scorer.scoreURL(url);
      
      expect(result.verdict).toBe('BLOCK');
      expect(result.score).toBeGreaterThanOrEqual(140);
      expect(result.reasons).toContain('Dangerous file extension');
      expect(result.reasons).toContain('Contains @ symbol (phishing attempt)');
      expect(result.reasons).toContain('IP address instead of domain');
      expect(result.reasons).toContain('Brand impersonation detected');
    });
  });

  describe('Real-world Scenarios', () => {
    test('should allow legitimate developer sites even if new', () => {
      const result = scorer.scoreURL('https://coolapp.io');
      
      expect(result.verdict).toBe('ALLOW');
      expect(result.reasons).not.toContain('New domain (less than 14 days)');
    });

    test('should block obvious phishing attempts', () => {
      const url = 'https://paypal-login-secure.xyz@malicious.com/steal.exe';
      const result = scorer.scoreURL(url);
      
      expect(result.verdict).toBe('BLOCK');
      expect(result.score).toBeGreaterThanOrEqual(120);
    });

    test('should warn about suspicious but not clearly malicious sites', () => {
      const url = 'http://192.168.1.1/admin';
      const result = scorer.scoreURL(url);
      
      expect(result.verdict).toBe('WARN');
      expect(result.score).toBe(20);
    });
  });
});

// Integration test for the complete flow
describe('URLRiskScorer Integration', () => {
  test('should demonstrate complete flow from suspicious to trusted', () => {
    const scorer = new URLRiskScorer();
    const suspiciousUrl = 'https://suspicious.xyz';
    
    // Phase 1: Not in any whitelist, proceed to scoring
    let result = scorer.scoreURL(suspiciousUrl);
    expect(result.verdict).toBe('WARN'); // 15 for .xyz + 25 for new domain = 40
    
    // Phase 4: User decides to unblock
    scorer.unblockURL(suspiciousUrl);
    
    // Phase 1: Now in personal trusted list
    result = scorer.scoreURL(suspiciousUrl);
    expect(result.verdict).toBe('ALLOW');
    expect(result.reasons).toContain('In personal trusted list');
  });
});
