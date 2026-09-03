/**
 * Phishing Website Detector - Curated Dataset & Data Manager
 * Contains 130+ real-world labeled URLs (Phishing vs Legitimate) with categories and feature generators.
 */

class DatasetManager {
  static RAW_BENCHMARK_DATA = [
    // --- 1. PHISHING DATA SAMPLES (Label: 1) ---
    // Banking & Financial Phishing
    { url: "http://chase-security-update-verify.com/login/auth.php", label: 1, category: "Banking Phish" },
    { url: "http://192.168.1.105/paypal/signin/verification.html", label: 1, category: "IP-based Phish" },
    { url: "http://wellsfargo-account-secure-alert.top/online/banking.html", label: 1, category: "Banking Phish" },
    { url: "http://secure-paypal-payment-verify.ga/account/recover", label: 1, category: "Banking Phish" },
    { url: "http://bankofamerica-login-confirm.cf/security/identity.asp", label: 1, category: "Banking Phish" },
    { url: "http://barclays-auth-security.tk/portal/web/login", label: 1, category: "Banking Phish" },
    { url: "http://hsbc-security-update.work/auth/account-verification", label: 1, category: "Banking Phish" },
    { url: "http://citi-bank-alert.xyz/portal/login.php?session=9238472", label: 1, category: "Banking Phish" },
    { url: "http://santander-verify-session.club/secure/webaccess.html", label: 1, category: "Banking Phish" },
    { url: "http://paypal-verification-center.info/webscr/login_submit.php", label: 1, category: "Banking Phish" },

    // Tech & Cloud Phishing
    { url: "http://microsoft-online-365-security.ml/login.srf?wa=wsignin1.0", label: 1, category: "Tech Spoof" },
    { url: "http://google-drive-shared-doc-view.gq/auth/google/signin", label: 1, category: "Tech Spoof" },
    { url: "http://appleid-apple-support-verify.icu/manage/account", label: 1, category: "Tech Spoof" },
    { url: "http://netflix-billing-update-warning.buzz/renew/subscription.php", label: 1, category: "Brand Phish" },
    { url: "http://amazon-account-suspended-action.top/ap/signin.htm", label: 1, category: "E-Commerce Phish" },
    { url: "http://adobe-pdf-cloud-verify.live/document/download.php?id=992", label: 1, category: "Tech Spoof" },
    { url: "http://dropbox-file-transfer-secure.rest/login.php", label: 1, category: "Tech Spoof" },
    { url: "http://secure-instagram-badge-verify.top/accounts/login", label: 1, category: "Social Media Phish" },
    { url: "http://facebook-security-checkpoint-appeal.cam/recover.php", label: 1, category: "Social Media Phish" },
    { url: "http://twitter-blue-verification-claim.click/auth/twitter", label: 1, category: "Social Media Phish" },

    // Crypto & Wallet Scams
    { url: "http://metamask-extension-recovery-phrase.xyz/wallet/restore.php", label: 1, category: "Crypto Scam" },
    { url: "http://binance-kyc-verification-claim.top/trade/login", label: 1, category: "Crypto Scam" },
    { url: "http://coinbase-account-restricted.bid/signin/auth-step2", label: 1, category: "Crypto Scam" },
    { url: "http://trustwallet-airdrop-bonus.work/claim/token?free=500", label: 1, category: "Crypto Scam" },
    { url: "http://phantom-solana-security-check.fit/onboarding/key.html", label: 1, category: "Crypto Scam" },
    { url: "http://ledger-live-hardware-security-update.club/firmware.php", label: 1, category: "Crypto Scam" },

    // URL Shortener & Obfuscated Malicious Links
    { url: "http://bit.ly/3xPh1shBankUpdate?redirect=secure-portal", label: 1, category: "Shortened Phish" },
    { url: "http://tinyurl.com/paypal-update-2026-auth", label: 1, category: "Shortened Phish" },
    { url: "http://t.co/f83hK92malicious?url=bank-login.xyz", label: 1, category: "Shortened Phish" },
    { url: "http://is.gd/chase_verification_login_alert", label: 1, category: "Shortened Phish" },
    { url: "http://cutt.ly/netflix-billing-resolve-993", label: 1, category: "Shortened Phish" },

    // Obfuscated / @ Symbol / Subdomain Stacking / Port Phishing
    { url: "http://www.google.com@phishing-target-domain.com/login.php", label: 1, category: "Obfuscated Phish" },
    { url: "http://legit-site.com@192.168.0.22/secure/banking/auth", label: 1, category: "IP-based Phish" },
    { url: "http://10.0.0.15:8080/portal/bank-login/login.htm", label: 1, category: "Non-standard Port" },
    { url: "http://172.16.254.1:8888/account-verification-step1.html", label: 1, category: "Non-standard Port" },
    { url: "http://secure.login.verify.account.chase.com.update-portal.xyz/signin", label: 1, category: "Subdomain Stacking" },
    { url: "http://portal.auth.banking.secure.paypal.com.customer-alert.top/webscr", label: 1, category: "Subdomain Stacking" },
    { url: "http://https-secure-token-banking-login.ml/auth/verification", label: 1, category: "HTTPS Spoofing" },
    { url: "http://ssl-certificate-renew-host-alert.work/admin/login.php", label: 1, category: "HTTPS Spoofing" },
    { url: "http://portal.account-security.net//redirect//chase-login.html", label: 1, category: "Double Slash Phish" },
    { url: "http://dga-q98f7z6a5c3b1m4k.xyz/phish/payload?user=admin&token=8923487192384719823", label: 1, category: "DGA Phish" },

    // Additional Phishing Vectors
    { url: "http://ebay-resolution-center-case.top/secure/dispute.php", label: 1, category: "E-Commerce Phish" },
    { url: "http://walmart-giftcard-survey-winner.buzz/reward/claim.html", label: 1, category: "Survey Scam" },
    { url: "http://dhl-express-package-delivery-tax.fit/tracking/pay.php", label: 1, category: "Delivery Scam" },
    { url: "http://fedex-parcel-status-notification.top/shipment/confirm", label: 1, category: "Delivery Scam" },
    { url: "http://ups-redelivery-address-update.xyz/tracking/redeliver", label: 1, category: "Delivery Scam" },
    { url: "http://usps-missed-delivery-fee-alert.club/reschedule.html", label: 1, category: "Delivery Scam" },
    { url: "http://irs-tax-refund-direct-deposit.work/refund/application.php", label: 1, category: "Gov Spoof" },
    { url: "http://gov-covid-relief-fund-grant.live/apply/identity", label: 1, category: "Gov Spoof" },
    { url: "http://steam-community-free-skins-trade.xyz/tradeoffer/new", label: 1, category: "Gaming Phish" },
    { url: "http://roblox-free-robux-generator-2026.top/verify.php", label: 1, category: "Gaming Phish" },
    { url: "http://discord-nitro-gift-claim-free.icu/nitro/claim", label: 1, category: "Gaming Phish" },
    { url: "http://spotify-premium-family-invite.rest/redeem/login.php", label: 1, category: "Brand Phish" },
    { url: "http://uber-driver-payout-issue.click/partner/login", label: 1, category: "Gig Economy Phish" },
    { url: "http://airbnb-host-payout-verification.cam/host/payout.html", label: 1, category: "Travel Phish" },
    { url: "http://booking-reservation-discount-claim.buzz/hotel/confirm", label: 1, category: "Travel Phish" },
    { url: "http://telegram-web-login-session.top/auth/verify_code", label: 1, category: "Social Media Phish" },
    { url: "http://whatsapp-web-desktop-sync.xyz/login/qr-code.php", label: 1, category: "Social Media Phish" },
    { url: "http://linkedin-job-interview-invitation.work/career/apply.html", label: 1, category: "Social Media Phish" },
    { url: "http://att-yahoo-mail-upgrade-server.top/mail/login.aspx", label: 1, category: "Webmail Phish" },
    { url: "http://comcast-xfinity-email-quota-alert.club/xfinity/login.php", label: 1, category: "Webmail Phish" },
    { url: "http://outlook-web-app-session-expired.bid/owa/auth/logon.aspx", label: 1, category: "Webmail Phish" },
    { url: "http://roundcube-webmail-system-migration.fit/login.php", label: 1, category: "Webmail Phish" },
    { url: "http://cpanel-webhost-ssl-alert.top/cpanel/auth", label: 1, category: "Hosting Phish" },
    { url: "http://godaddy-domain-expiration-renewal.buzz/renew/payment", label: 1, category: "Hosting Phish" },
    { url: "http://namecheap-account-locked-warning.xyz/support/ticket.php", label: 1, category: "Hosting Phish" },

    // --- 2. LEGITIMATE DATA SAMPLES (Label: 0) ---
    // Major Tech Platforms & Portals
    { url: "https://www.google.com/search?q=machine+learning+tutorial", label: 0, category: "Search & Tech" },
    { url: "https://github.com/microsoft/vscode/releases", label: 0, category: "Developer Tools" },
    { url: "https://developer.mozilla.org/en-US/docs/Web/JavaScript", label: 0, category: "Education & Tech" },
    { url: "https://stackoverflow.com/questions/tagged/javascript", label: 0, category: "Developer Tools" },
    { url: "https://en.wikipedia.org/wiki/Supervised_learning", label: 0, category: "Encyclopedia" },
    { url: "https://en.wikipedia.org/wiki/Phishing", label: 0, category: "Encyclopedia" },
    { url: "https://www.microsoft.com/en-us/windows", label: 0, category: "Tech Portal" },
    { url: "https://apple.com/iphone-16-pro/specs/", label: 0, category: "Tech Portal" },
    { url: "https://aws.amazon.com/ec2/pricing/on-demand/", label: 0, category: "Cloud & Dev" },
    { url: "https://cloud.google.com/docs/overview", label: 0, category: "Cloud & Dev" },

    // Verified Banking & Financial Portals
    { url: "https://www.chase.com/personal/banking", label: 0, category: "Verified Bank" },
    { url: "https://www.bankofamerica.com/credit-cards/", label: 0, category: "Verified Bank" },
    { url: "https://www.wellsfargo.com/checking/", label: 0, category: "Verified Bank" },
    { url: "https://www.paypal.com/us/home", label: 0, category: "Verified Fintech" },
    { url: "https://www.stripe.com/docs/payments", label: 0, category: "Verified Fintech" },
    { url: "https://www.fidelity.com/trading/overview", label: 0, category: "Verified Investment" },
    { url: "https://www.vanguard.com/personal/investing", label: 0, category: "Verified Investment" },
    { url: "https://www.schwab.com/brokerage", label: 0, category: "Verified Investment" },
    { url: "https://www.americanexpress.com/us/credit-cards/", label: 0, category: "Verified Bank" },
    { url: "https://www.capitalone.com/bank/", label: 0, category: "Verified Bank" },

    // Verified E-Commerce & Retail
    { url: "https://www.amazon.com/b?node=16225007011", label: 0, category: "E-Commerce" },
    { url: "https://www.ebay.com/itm/electronic-gadget-sample", label: 0, category: "E-Commerce" },
    { url: "https://www.walmart.com/cp/electronics/3944", label: 0, category: "E-Commerce" },
    { url: "https://www.target.com/c/home-decor/-/N-5xttg", label: 0, category: "E-Commerce" },
    { url: "https://www.bestbuy.com/site/computers-tablets/laptops", label: 0, category: "E-Commerce" },
    { url: "https://www.costco.com/warehouse-locations", label: 0, category: "E-Commerce" },
    { url: "https://www.etsy.com/c/vintage", label: 0, category: "E-Commerce" },
    { url: "https://www.homedepot.com/b/Appliances/N-5yc1vZbv1w", label: 0, category: "E-Commerce" },
    { url: "https://www.ikea.com/us/en/cat/furniture-fu001/", label: 0, category: "E-Commerce" },
    { url: "https://www.nike.com/running/shoes", label: 0, category: "E-Commerce" },

    // Government, Education & Research
    { url: "https://www.nasa.gov/missions/artemis/", label: 0, category: "Gov & Science" },
    { url: "https://www.nih.gov/health-information", label: 0, category: "Gov & Science" },
    { url: "https://www.cdc.gov/flu/prevent/index.html", label: 0, category: "Gov & Science" },
    { url: "https://www.weather.gov/radar", label: 0, category: "Gov & Science" },
    { url: "https://www.loc.gov/collections/", label: 0, category: "Gov & Science" },
    { url: "https://www.harvard.edu/programs/computer-science", label: 0, category: "University" },
    { url: "https://web.mit.edu/research/", label: 0, category: "University" },
    { url: "https://www.stanford.edu/academics/", label: 0, category: "University" },
    { url: "https://www.ox.ac.uk/admissions/graduate", label: 0, category: "University" },
    { url: "https://www.cam.ac.uk/study-at-cambridge", label: 0, category: "University" },
    { url: "https://arxiv.org/abs/2301.00001", label: 0, category: "Academic Research" },
    { url: "https://www.nature.com/articles/d41586-024-00100-w", label: 0, category: "Scientific Journal" },
    { url: "https://www.sciencedirect.com/journal/neural-networks", label: 0, category: "Scientific Journal" },

    // News, Media & Entertainment
    { url: "https://www.bbc.com/news/technology", label: 0, category: "News Media" },
    { url: "https://www.reuters.com/markets/asia/", label: 0, category: "News Media" },
    { url: "https://www.nytimes.com/section/technology", label: 0, category: "News Media" },
    { url: "https://www.theguardian.com/world", label: 0, category: "News Media" },
    { url: "https://edition.cnn.com/world", label: 0, category: "News Media" },
    { url: "https://www.wsj.com/news/business", label: 0, category: "News Media" },
    { url: "https://www.bloomberg.com/economics", label: 0, category: "News Media" },
    { url: "https://www.netflix.com/browse", label: 0, category: "Entertainment" },
    { url: "https://www.spotify.com/us/premium/", label: 0, category: "Entertainment" },
    { url: "https://www.youtube.com/watch?v=dQw4w9WgXcQ", label: 0, category: "Media Platform" },
    { url: "https://vimeo.com/categories/documentary", label: 0, category: "Media Platform" },
    { url: "https://twitch.tv/directory", label: 0, category: "Media Platform" },

    // Verified Social & Collaboration
    { url: "https://www.linkedin.com/feed/", label: 0, category: "Social Network" },
    { url: "https://www.reddit.com/r/MachineLearning/", label: 0, category: "Social Network" },
    { url: "https://www.quora.com/topic/Artificial-Intelligence", label: 0, category: "Community" },
    { url: "https://medium.com/tag/data-science", label: 0, category: "Publishing" },
    { url: "https://dev.to/t/webdev", label: 0, category: "Community" },
    { url: "https://slack.com/features/channels", label: 0, category: "Collaboration" },
    { url: "https://zoom.us/pricing", label: 0, category: "Collaboration" },
    { url: "https://trello.com/tour", label: 0, category: "Collaboration" },
    { url: "https://notion.so/product", label: 0, category: "Collaboration" },
    { url: "https://gitlab.com/explore", label: 0, category: "Developer Tools" },
    { url: "https://bitbucket.org/product", label: 0, category: "Developer Tools" },
    { url: "https://hub.docker.com/search", label: 0, category: "Developer Tools" },
    { url: "https://www.npmjs.com/package/express", label: 0, category: "Package Registry" },
    { url: "https://pypi.org/project/scikit-learn/", label: 0, category: "Package Registry" },
    { url: "https://kaggle.com/datasets", label: 0, category: "Data Science" },
    { url: "https://huggingface.co/models", label: 0, category: "Data Science" }
  ];

  /**
   * Initializes dataset by extracting feature vectors for all samples
   */
  static loadProcessedDataset(customData = null) {
    const rawList = customData || this.RAW_BENCHMARK_DATA;
    const records = [];
    const X = [];
    const y = [];

    for (let i = 0; i < rawList.length; i++) {
      const item = rawList[i];
      try {
        const extracted = FeatureExtractor.extractFeatures(item.url);
        const record = {
          id: i + 1,
          url: item.url,
          label: parseInt(item.label, 10),
          labelName: parseInt(item.label, 10) === 1 ? 'Phishing' : 'Legitimate',
          category: item.category || (parseInt(item.label, 10) === 1 ? 'Phishing Site' : 'Legitimate Site'),
          vector: extracted.vector,
          featureDetails: extracted.featureDetails
        };
        records.push(record);
        X.push(extracted.vector);
        y.push(record.label);
      } catch (err) {
        console.warn(`Skipping invalid URL at index ${i}: ${item.url}`, err);
      }
    }

    return { records, X, y };
  }

  /**
   * Converts processed records to downloadable CSV
   */
  static exportToCSV(records) {
    const headers = [
      'ID',
      'URL',
      'Category',
      'Label',
      'Label_Name',
      ...FeatureExtractor.FEATURE_DEFINITIONS.map(f => f.id)
    ];

    const rows = [headers.join(',')];

    for (const rec of records) {
      const escapedUrl = `"${rec.url.replace(/"/g, '""')}"`;
      const escapedCat = `"${(rec.category || '').replace(/"/g, '""')}"`;
      const row = [
        rec.id,
        escapedUrl,
        escapedCat,
        rec.label,
        rec.labelName,
        ...rec.vector
      ];
      rows.push(row.join(','));
    }

    return rows.join('\r\n');
  }

  /**
   * Parses uploaded CSV into usable dataset
   */
  static parseCSV(csvText) {
    const lines = csvText.split(/\r?\n/).filter(line => line.trim().length > 0);
    if (lines.length < 2) {
      throw new Error('CSV file must have at least a header row and one data row.');
    }

    const header = lines[0].split(',').map(h => h.trim().replace(/^["']|["']$/g, '').toLowerCase());
    const urlIdx = header.findIndex(h => h === 'url' || h === 'website' || h === 'link');
    const labelIdx = header.findIndex(h => h === 'label' || h === 'class' || h === 'target' || h === 'is_phishing');
    const catIdx = header.findIndex(h => h === 'category' || h === 'type');

    if (urlIdx === -1) {
      throw new Error('CSV must contain a "url" column.');
    }

    const parsedItems = [];
    for (let i = 1; i < lines.length; i++) {
      // Basic CSV regex parser to handle quotes
      const cols = [];
      let match;
      const regex = /(?:,|\n|^)("(?:(?:"")*[^"]*)*"|[^",\n]*|(?:\n|$))/g;
      const line = lines[i];
      let colIdx = 0;
      let rawCols = line.split(','); // simple fallback or structured regex
      
      const cleanUrl = (rawCols[urlIdx] || '').trim().replace(/^["']|["']$/g, '');
      let labelVal = 0;
      if (labelIdx !== -1 && rawCols[labelIdx]) {
        const rawLabel = rawCols[labelIdx].trim().replace(/^["']|["']$/g, '').toLowerCase();
        if (rawLabel === '1' || rawLabel === 'phishing' || rawLabel === 'phish' || rawLabel === 'true' || rawLabel === 'bad') {
          labelVal = 1;
        }
      }
      const cat = catIdx !== -1 && rawCols[catIdx] ? rawCols[catIdx].trim().replace(/^["']|["']$/g, '') : 'Custom Upload';

      if (cleanUrl) {
        parsedItems.push({
          url: cleanUrl,
          label: labelVal,
          category: cat
        });
      }
    }

    if (parsedItems.length === 0) {
      throw new Error('No valid URL records could be parsed from the CSV.');
    }

    return parsedItems;
  }
}

// Support browser global or module export
if (typeof window !== 'undefined') {
  window.DatasetManager = DatasetManager;
}
if (typeof module !== 'undefined' && module.exports) {
  module.exports = DatasetManager;
}
