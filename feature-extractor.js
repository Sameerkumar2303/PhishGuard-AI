/**
 * Phishing Website Detector - URL Feature Extractor
 * Extracts 15 lexical, structural, and heuristic features from any URL string.
 */

class FeatureExtractor {
  static FEATURE_DEFINITIONS = [
    {
      id: 'url_length',
      name: 'URL Length',
      description: 'Phishing URLs are often unusually long to obscure destination.',
      type: 'numeric',
      normalRange: '10 - 54 characters',
      weight: 1.2
    },
    {
      id: 'has_ip',
      name: 'IP Address as Host',
      description: 'Using raw IP (e.g. 192.168.1.1) instead of domain name is strongly indicative of malicious intent.',
      type: 'binary',
      normalRange: '0 (Domain name used)',
      weight: 2.5
    },
    {
      id: 'is_shortened',
      name: 'URL Shortening Service',
      description: 'Shorteners (bit.ly, tinyurl, etc.) hide the actual destination URL.',
      type: 'binary',
      normalRange: '0 (Not shortened)',
      weight: 1.8
    },
    {
      id: 'has_at_symbol',
      name: '@ Symbol in URL',
      description: 'The @ character causes the browser to ignore everything before it, tricking users.',
      type: 'binary',
      normalRange: '0 (No @ symbol)',
      weight: 2.2
    },
    {
      id: 'double_slash_redirect',
      name: 'Double Slash Redirection',
      description: 'Use of // after protocol redirection tricks users on the destination host.',
      type: 'binary',
      normalRange: '0 (Only protocol //)',
      weight: 1.6
    },
    {
      id: 'prefix_suffix_hyphen',
      name: 'Prefix/Suffix Hyphen in Domain',
      description: 'Phishers add hyphens (e.g. paypal-security.com) to mimic genuine brands.',
      type: 'binary',
      normalRange: '0 (No hyphens in host)',
      weight: 1.5
    },
    {
      id: 'subdomain_count',
      name: 'Subdomain Depth',
      description: 'Legitimate sites rarely exceed 1-2 subdomains; phishers stack multiple subdomains.',
      type: 'numeric',
      normalRange: '0 - 2 subdomains',
      weight: 1.4
    },
    {
      id: 'https_token_spoof',
      name: 'HTTPS Token in Domain Name',
      description: 'Embedding "https" or "ssl" in the domain name (e.g., https-chase-update.com).',
      type: 'binary',
      normalRange: '0 (No fake token)',
      weight: 2.0
    },
    {
      id: 'sensitive_keywords_count',
      name: 'Sensitive Keywords Score',
      description: 'Count of keywords like login, verify, account, secure, bank, payment, signin, update.',
      type: 'numeric',
      normalRange: '0 keywords',
      weight: 1.7
    },
    {
      id: 'non_standard_port',
      name: 'Non-Standard Port',
      description: 'Phishing servers occasionally run on non-standard ports (e.g., :8080, :8888, :81).',
      type: 'binary',
      normalRange: '0 (Standard 80/443)',
      weight: 1.3
    },
    {
      id: 'suspicious_tld',
      name: 'Suspicious / Free TLD',
      description: 'TLDs frequently abused for free spam/phishing (.xyz, .top, .work, .tk, .ml, .ga, .cf, .gq).',
      type: 'binary',
      normalRange: '0 (Standard TLD)',
      weight: 1.9
    },
    {
      id: 'shannon_entropy',
      name: 'Character Entropy (Randomness)',
      description: 'High randomness indicates machine-generated algorithmically generated domains (DGA).',
      type: 'numeric',
      normalRange: '2.5 - 4.2 bits',
      weight: 1.1
    },
    {
      id: 'digit_ratio',
      name: 'Digit-to-Letter Ratio',
      description: 'Proportion of numeric digits in the domain and path.',
      type: 'numeric',
      normalRange: '0.0 - 0.15',
      weight: 1.3
    },
    {
      id: 'special_char_count',
      name: 'Special Characters Count',
      description: 'Frequent use of %, ?, =, &, _, ~ in URLs to obfuscate or inject parameters.',
      type: 'numeric',
      normalRange: '0 - 4 symbols',
      weight: 1.1
    },
    {
      id: 'path_depth',
      name: 'URL Path Depth',
      description: 'Number of directory levels in the URL path (e.g. /a/b/c/d/login.html).',
      type: 'numeric',
      normalRange: '0 - 2 levels',
      weight: 1.0
    }
  ];

  static SHORTENER_DOMAINS = new Set([
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 
    'adf.ly', 'bit.do', 'cutt.ly', 'tiny.cc', 'rb.gy', 'shorte.st', 't.ly'
  ]);

  static SUSPICIOUS_TLDS = new Set([
    'xyz', 'top', 'work', 'club', 'tk', 'ml', 'ga', 'cf', 'gq', 'fit', 
    'rest', 'surf', 'buzz', 'live', 'click', 'link', 'icu', 'cam', 'bid'
  ]);

  static SENSITIVE_KEYWORDS = [
    'login', 'signin', 'verify', 'verification', 'secure', 'account', 'banking', 
    'update', 'confirm', 'password', 'credential', 'auth', 'recover', 'wallet', 
    'paypal', 'ebay', 'amazon', 'appleid', 'microsoft', 'netflix', 'chase', 'wellsfargo'
  ];

  /**
   * Normalizes and parses raw URL string into safe URL object and parts
   */
  static parseUrl(rawUrl) {
    let cleanUrl = (rawUrl || '').trim();
    if (!cleanUrl) {
      throw new Error('URL string cannot be empty.');
    }

    if (!/^https?:\/\//i.test(cleanUrl)) {
      cleanUrl = 'http://' + cleanUrl;
    }

    try {
      const parsed = new URL(cleanUrl);
      return {
        url: cleanUrl,
        protocol: parsed.protocol.replace(':', '').toLowerCase(),
        hostname: parsed.hostname.toLowerCase(),
        pathname: parsed.pathname,
        search: parsed.search,
        port: parsed.port,
        hash: parsed.hash
      };
    } catch (e) {
      // Fallback parsing for malformed URLs
      const match = cleanUrl.match(/^(?:(https?):\/\/)?([^\/\?#:]+)(?::(\d+))?([^?#]*)(\?[^#]*)?(#.*)?$/i);
      if (!match) {
        throw new Error('Invalid URL format could not be parsed.');
      }
      return {
        url: cleanUrl,
        protocol: (match[1] || 'http').toLowerCase(),
        hostname: (match[2] || '').toLowerCase(),
        port: match[3] || '',
        pathname: match[4] || '/',
        search: match[5] || '',
        hash: match[6] || ''
      };
    }
  }

  /**
   * Calculates Shannon Entropy of a string
   */
  static calculateEntropy(str) {
    if (!str || str.length === 0) return 0;
    const len = str.length;
    const frequencies = {};
    for (let i = 0; i < len; i++) {
      const char = str[i];
      frequencies[char] = (frequencies[char] || 0) + 1;
    }

    let entropy = 0;
    for (const char in frequencies) {
      const p = frequencies[char] / len;
      entropy -= p * Math.log2(p);
    }
    return parseFloat(entropy.toFixed(3));
  }

  /**
   * Extracts all 15 features from a raw URL and returns feature vector and human readable diagnostics
   */
  static extractFeatures(rawUrl) {
    const parsed = this.parseUrl(rawUrl);
    const fullUrl = parsed.url;
    const hostname = parsed.hostname;
    const path = parsed.pathname;
    const query = parsed.search;

    // Feature 1: URL Length
    const urlLength = fullUrl.length;

    // Feature 2: IP Address in Hostname
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const ipv6Regex = /^\[?[0-9a-fA-F:]+\]?$/;
    const hasIp = (ipv4Regex.test(hostname) || (hostname.includes(':') && ipv6Regex.test(hostname))) ? 1 : 0;

    // Feature 3: URL Shortener
    const isShortened = this.SHORTENER_DOMAINS.has(hostname) || this.SHORTENER_DOMAINS.has(hostname.replace(/^www\./, '')) ? 1 : 0;

    // Feature 4: @ Symbol in URL
    const hasAtSymbol = fullUrl.includes('@') ? 1 : 0;

    // Feature 5: Double Slash Redirect in path (after protocol)
    const doubleSlashRedirect = path.includes('//') ? 1 : 0;

    // Feature 6: Prefix or Suffix '-' in Domain Name
    const prefixSuffixHyphen = hostname.includes('-') ? 1 : 0;

    // Feature 7: Subdomain Count
    const hostParts = hostname.split('.').filter(Boolean);
    let subdomainCount = 0;
    if (hasIp) {
      subdomainCount = 0;
    } else if (hostParts.length > 2) {
      subdomainCount = Math.max(0, hostParts.length - 2);
    }

    // Feature 8: HTTPS token spoofing in domain (e.g. login-https.com)
    const httpsTokenSpoof = (hostname.includes('https') || hostname.includes('ssl') || hostname.includes('tls')) ? 1 : 0;

    // Feature 9: Sensitive Keywords Count
    let sensitiveCount = 0;
    const lowerFullUrl = fullUrl.toLowerCase();
    for (const kw of this.SENSITIVE_KEYWORDS) {
      if (lowerFullUrl.includes(kw)) {
        sensitiveCount++;
      }
    }

    // Feature 10: Non-standard Port
    let nonStandardPort = 0;
    if (parsed.port && parsed.port !== '80' && parsed.port !== '443') {
      nonStandardPort = 1;
    }

    // Feature 11: Suspicious / Abused TLD
    const tld = hostParts.length > 0 ? hostParts[hostParts.length - 1] : '';
    const suspiciousTld = this.SUSPICIOUS_TLDS.has(tld) ? 1 : 0;

    // Feature 12: Shannon Entropy of full URL
    const shannonEntropy = this.calculateEntropy(fullUrl);

    // Feature 13: Digit-to-Letter Ratio
    const digits = (fullUrl.match(/\d/g) || []).length;
    const letters = (fullUrl.match(/[a-zA-Z]/g) || []).length;
    const digitRatio = letters > 0 ? parseFloat((digits / letters).toFixed(3)) : (digits > 0 ? 1 : 0);

    // Feature 14: Special Characters Count
    const specialChars = (fullUrl.match(/[?=%&_~#+]/g) || []).length;

    // Feature 15: Path Depth (Directory Levels)
    const pathSegments = path.split('/').filter(Boolean);
    const pathDepth = pathSegments.length;

    // Ordered numerical feature vector for ML models
    const vector = [
      urlLength,
      hasIp,
      isShortened,
      hasAtSymbol,
      doubleSlashRedirect,
      prefixSuffixHyphen,
      subdomainCount,
      httpsTokenSpoof,
      sensitiveCount,
      nonStandardPort,
      suspiciousTld,
      shannonEntropy,
      digitRatio,
      specialChars,
      pathDepth
    ];

    // Detailed diagnostic object for UI rendering and XAI
    const featureDetails = [
      {
        id: 'url_length',
        name: 'URL Length',
        value: urlLength,
        display: `${urlLength} chars`,
        isSuspicious: urlLength > 54,
        severity: urlLength > 75 ? 'high' : (urlLength > 54 ? 'medium' : 'safe'),
        explanation: urlLength > 54 ? 'Excessive length is common in obfuscated phishing links.' : 'Length within normal standard limits.'
      },
      {
        id: 'has_ip',
        name: 'IP Address as Host',
        value: hasIp,
        display: hasIp ? 'Yes (IP Used)' : 'No (Domain Name)',
        isSuspicious: hasIp === 1,
        severity: hasIp === 1 ? 'critical' : 'safe',
        explanation: hasIp === 1 ? 'Legitimate sites rarely use raw IP addresses in consumer URLs.' : 'Standard host domain resolution.'
      },
      {
        id: 'is_shortened',
        name: 'URL Shortener Service',
        value: isShortened,
        display: isShortened ? 'Yes (Shortened)' : 'No (Direct)',
        isSuspicious: isShortened === 1,
        severity: isShortened === 1 ? 'high' : 'safe',
        explanation: isShortened === 1 ? 'Shortened links mask actual endpoint and bypass domain inspection.' : 'Direct, transparent domain destination.'
      },
      {
        id: 'has_at_symbol',
        name: '@ Symbol in URL',
        value: hasAtSymbol,
        display: hasAtSymbol ? 'Detected' : 'None',
        isSuspicious: hasAtSymbol === 1,
        severity: hasAtSymbol === 1 ? 'critical' : 'safe',
        explanation: hasAtSymbol === 1 ? '@ symbol causes browser to ignore preceding credentials.' : 'No credential obfuscation detected.'
      },
      {
        id: 'double_slash_redirect',
        name: 'Double Slash Redirection',
        value: doubleSlashRedirect,
        display: doubleSlashRedirect ? 'Detected in Path' : 'Normal',
        isSuspicious: doubleSlashRedirect === 1,
        severity: doubleSlashRedirect === 1 ? 'high' : 'safe',
        explanation: doubleSlashRedirect === 1 ? 'Internal // redirection pattern found.' : 'Standard path hierarchy.'
      },
      {
        id: 'prefix_suffix_hyphen',
        name: 'Hyphen in Hostname',
        value: prefixSuffixHyphen,
        display: prefixSuffixHyphen ? 'Yes' : 'No',
        isSuspicious: prefixSuffixHyphen === 1,
        severity: prefixSuffixHyphen === 1 ? 'medium' : 'safe',
        explanation: prefixSuffixHyphen === 1 ? 'Phishers frequently combine brand names with hyphens (e.g., paypal-secure).' : 'Clean hostname syntax.'
      },
      {
        id: 'subdomain_count',
        name: 'Subdomain Count',
        value: subdomainCount,
        display: `${subdomainCount} subdomains`,
        isSuspicious: subdomainCount > 2,
        severity: subdomainCount > 3 ? 'high' : (subdomainCount > 2 ? 'medium' : 'safe'),
        explanation: subdomainCount > 2 ? 'Deep subdomain stacking is often used to deceive users.' : 'Normal subdomain hierarchy.'
      },
      {
        id: 'https_token_spoof',
        name: 'HTTPS Token in Domain',
        value: httpsTokenSpoof,
        display: httpsTokenSpoof ? 'Yes (Spoofed Token)' : 'None',
        isSuspicious: httpsTokenSpoof === 1,
        severity: httpsTokenSpoof === 1 ? 'high' : 'safe',
        explanation: httpsTokenSpoof === 1 ? 'Fake "https" or "ssl" keyword embedded inside the domain name.' : 'Clean domain identity.'
      },
      {
        id: 'sensitive_keywords_count',
        name: 'Sensitive Keyword Matches',
        value: sensitiveCount,
        display: `${sensitiveCount} keywords`,
        isSuspicious: sensitiveCount >= 2,
        severity: sensitiveCount >= 3 ? 'high' : (sensitiveCount >= 1 ? 'medium' : 'safe'),
        explanation: sensitiveCount > 0 ? `Targeted credentials keywords matched in URL.` : 'No phishing lure keywords detected.'
      },
      {
        id: 'non_standard_port',
        name: 'Non-Standard Port',
        value: nonStandardPort,
        display: nonStandardPort ? `Port ${parsed.port}` : 'Standard (80/443)',
        isSuspicious: nonStandardPort === 1,
        severity: nonStandardPort === 1 ? 'medium' : 'safe',
        explanation: nonStandardPort === 1 ? 'Uncommon port number used.' : 'Default web ports utilized.'
      },
      {
        id: 'suspicious_tld',
        name: 'Suspicious / Free TLD',
        value: suspiciousTld,
        display: suspiciousTld ? `.${tld} (High Risk)` : `.${tld || 'com'} (Standard)`,
        isSuspicious: suspiciousTld === 1,
        severity: suspiciousTld === 1 ? 'high' : 'safe',
        explanation: suspiciousTld === 1 ? 'TLD has high statistical abuse rate in phishing campaigns.' : 'Reputable top-level domain.'
      },
      {
        id: 'shannon_entropy',
        name: 'Character Entropy',
        value: shannonEntropy,
        display: `${shannonEntropy} bits`,
        isSuspicious: shannonEntropy > 4.5,
        severity: shannonEntropy > 4.8 ? 'high' : (shannonEntropy > 4.3 ? 'medium' : 'safe'),
        explanation: shannonEntropy > 4.5 ? 'High randomness suggests DGA or encoded hash strings.' : 'Natural human-readable text distribution.'
      },
      {
        id: 'digit_ratio',
        name: 'Digit-to-Letter Ratio',
        value: digitRatio,
        display: `${(digitRatio * 100).toFixed(1)}%`,
        isSuspicious: digitRatio > 0.3,
        severity: digitRatio > 0.5 ? 'high' : (digitRatio > 0.25 ? 'medium' : 'safe'),
        explanation: digitRatio > 0.3 ? 'Unusually high ratio of digits in URL.' : 'Normal alphanumeric ratio.'
      },
      {
        id: 'special_char_count',
        name: 'Special Characters Count',
        value: specialChars,
        display: `${specialChars} symbols`,
        isSuspicious: specialChars > 5,
        severity: specialChars > 8 ? 'high' : (specialChars > 4 ? 'medium' : 'safe'),
        explanation: specialChars > 5 ? 'High parameter density or character encoding obfuscation.' : 'Standard URL syntax density.'
      },
      {
        id: 'path_depth',
        name: 'Path Directory Depth',
        value: pathDepth,
        display: `${pathDepth} levels`,
        isSuspicious: pathDepth > 4,
        severity: pathDepth > 5 ? 'high' : (pathDepth > 3 ? 'medium' : 'safe'),
        explanation: pathDepth > 4 ? 'Deep directory nested structures used to hide payload files.' : 'Normal directory depth.'
      }
    ];

    return {
      rawUrl,
      parsed,
      vector,
      featureDetails
    };
  }
}

// Support browser global or module export
if (typeof window !== 'undefined') {
  window.FeatureExtractor = FeatureExtractor;
}
if (typeof module !== 'undefined' && module.exports) {
  module.exports = FeatureExtractor;
}
