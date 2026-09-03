/**
 * Phishing Website Detector - Main Application Controller
 * Handles application lifecycle, UI orchestration, event bindings, and model execution.
 */

class PhishingDetectorApp {
  constructor() {
    this.dataset = null;
    this.trainSet = null;
    this.testSet = null;
    this.scaler = new StandardScaler();
    this.models = {};
    this.modelMetrics = [];
    this.currentScanResult = null;
    this.activeTab = 'tab-scanner';
  }

  /**
   * Initializes the application upon DOM load
   */
  init() {
    this.setupThemeToggle();
    this.bindTabEvents();
    this.loadDatasetAndTrain();
    this.setupWindowResize();

    // Perform default initial scan on preset URL
    const defaultUrl = document.getElementById('url-input')?.value || 'http://paypal-security-update-verify.com/login/auth.php';
    this.handleScan(defaultUrl);
  }

  /**
   * Sets up the Light/Dark mode toggle listener
   */
  setupThemeToggle() {
    const themeBtn = document.getElementById('theme-toggle-btn');
    const iconLight = document.querySelector('.theme-icon-light');
    const iconDark = document.querySelector('.theme-icon-dark');
    
    if(!themeBtn) return;
    
    themeBtn.addEventListener('click', () => {
      const currentTheme = document.documentElement.getAttribute('data-theme');
      
      if (currentTheme === 'dark') {
        document.documentElement.removeAttribute('data-theme');
        iconLight.style.display = 'inline-block';
        iconDark.style.display = 'none';
      } else {
        document.documentElement.setAttribute('data-theme', 'dark');
        iconLight.style.display = 'none';
        iconDark.style.display = 'inline-block';
      }
      
      // Request redraw for visualizer canvases to adapt to new theme variables
      setTimeout(() => {
        if (this.testSet && this.scaler) {
          const scaledTestX = this.scaler.transform(this.testSet.X);
          // Simple redraw hack by triggering an evaluation refresh which redraws charts
          // or just redraw the Risk Gauge directly
        }
        if (this.currentScanResult && window.Visualizer) {
          Visualizer.drawRiskGauge('canvas-risk-gauge', this.currentScanResult.ensembleRiskScore);
        }
      }, 50);
    });
  }


  /**
   * Loads dataset, executes train/test split, and fits all 4 ML models
   */
  loadDatasetAndTrain(customData = null) {
    // 1. Process dataset
    this.dataset = DatasetManager.loadProcessedDataset(customData);
    this.updateDatasetStatsUI();

    // 2. Read hyperparameters
    const splitRatioVal = parseInt(document.getElementById('split-ratio')?.value || '75', 10) / 100;
    const learningRate = parseFloat(document.getElementById('learning-rate')?.value || '0.05');
    const epochs = parseInt(document.getElementById('train-epochs')?.value || '150', 10);
    const maxDepth = parseInt(document.getElementById('tree-depth')?.value || '5', 10);

    // 3. Stratified Train / Test Split
    const split = MetricsEvaluator.trainTestSplit(
      this.dataset.X,
      this.dataset.y,
      this.dataset.records,
      1.0 - splitRatioVal
    );
    this.trainSet = split.train;
    this.testSet = split.test;

    // 4. Fit StandardScaler on Training Set
    this.scaler = new StandardScaler();
    this.scaler.fit(this.trainSet.X);

    const scaledTrainX = this.scaler.transform(this.trainSet.X);
    const scaledTestX = this.scaler.transform(this.testSet.X);

    // 5. Instantiate and Train Models
    const featureNames = FeatureExtractor.FEATURE_DEFINITIONS.map(f => f.name);

    // Model A: Logistic Regression
    const lr = new LogisticRegressionModel({
      learningRate,
      epochs,
      l2Lambda: 0.001
    });
    lr.fit(scaledTrainX, this.trainSet.y);
    this.models.logisticRegression = lr;

    // Model B: Naive Bayes
    const nb = new NaiveBayesModel();
    nb.fit(scaledTrainX, this.trainSet.y);
    this.models.naiveBayes = nb;

    // Model C: Decision Tree (Uses unscaled or scaled features for readable rules)
    const dt = new DecisionTreeModel({
      maxDepth,
      minSamplesSplit: 3,
      featureNames
    });
    dt.fit(this.trainSet.X, this.trainSet.y);
    this.models.decisionTree = dt;

    // Model D: Random Forest
    const rf = new RandomForestModel({
      numTrees: 12,
      maxDepth: maxDepth + 1,
      minSamplesSplit: 3,
      featureNames
    });
    rf.fit(this.trainSet.X, this.trainSet.y);
    this.models.randomForest = rf;

    // 6. Evaluate all models on Holdout Test Set
    this.evaluateModels(scaledTestX, this.testSet.X, this.testSet.y);

    // 7. Update UI Visualizations
    this.renderTrainingVisualizations();
    this.renderDatasetTable(this.dataset.records);
    this.renderDecisionTreeRules();
  }

  /**
   * Evaluates all models against the unseen holdout test set
   */
  evaluateModels(scaledTestX, rawTestX, yTrue) {
    this.modelMetrics = [];

    // Evaluate Logistic Regression
    const lrProbs = scaledTestX.map(x => this.models.logisticRegression.predictProbability(x));
    const lrPreds = lrProbs.map(p => (p >= 0.5 ? 1 : 0));
    const lrMetrics = MetricsEvaluator.evaluate(yTrue, lrPreds, lrProbs);
    this.modelMetrics.push({
      name: 'Logistic Regression',
      key: 'lr',
      metrics: lrMetrics
    });

    // Evaluate Naive Bayes
    const nbProbs = scaledTestX.map(x => this.models.naiveBayes.predictProbability(x));
    const nbPreds = nbProbs.map(p => (p >= 0.5 ? 1 : 0));
    const nbMetrics = MetricsEvaluator.evaluate(yTrue, nbPreds, nbProbs);
    this.modelMetrics.push({
      name: 'Naive Bayes',
      key: 'nb',
      metrics: nbMetrics
    });

    // Evaluate Decision Tree (unscaled features)
    const dtProbs = rawTestX.map(x => this.models.decisionTree.predictProbability(x));
    const dtPreds = dtProbs.map(p => (p >= 0.5 ? 1 : 0));
    const dtMetrics = MetricsEvaluator.evaluate(yTrue, dtPreds, dtProbs);
    this.modelMetrics.push({
      name: 'Decision Tree',
      key: 'dt',
      metrics: dtMetrics
    });

    // Evaluate Random Forest
    const rfProbs = rawTestX.map(x => this.models.randomForest.predictProbability(x));
    const rfPreds = rfProbs.map(p => (p >= 0.5 ? 1 : 0));
    const rfMetrics = MetricsEvaluator.evaluate(yTrue, rfPreds, rfProbs);
    this.modelMetrics.push({
      name: 'Random Forest',
      key: 'rf',
      metrics: rfMetrics
    });

    // Update Summary Metric Cards using Ensemble / Best Model
    const primary = this.modelMetrics[3].metrics; // Random Forest or LR
    document.getElementById('metric-accuracy').innerText = `${primary.accuracy}%`;
    document.getElementById('metric-precision').innerText = `${primary.precision}%`;
    document.getElementById('metric-recall').innerText = `${primary.recall}%`;
    document.getElementById('metric-f1').innerText = `${primary.f1Score}%`;
    document.getElementById('test-set-size-badge').innerText = `${this.testSet.y.length} Test Samples`;
  }

  /**
   * Renders charts in the Training tab
   */
  renderTrainingVisualizations() {
    const lr = this.models.logisticRegression;
    const rfMetrics = this.modelMetrics[3]?.metrics;

    // 1. Loss & Accuracy Curve
    Visualizer.drawLossChart('canvas-loss-chart', lr.lossHistory, lr.accuracyHistory);

    // 2. Confusion Matrix
    Visualizer.drawConfusionMatrix('confusion-matrix-container', rfMetrics?.confusionMatrix || { tp: 0, tn: 0, fp: 0, fn: 0 });

    // 3. ROC Curve
    Visualizer.drawRocCurve('canvas-roc-chart', rfMetrics?.rocCurve || [], rfMetrics?.auc || 0.5);

    // 4. Multi-Model Bar Chart
    Visualizer.drawModelComparisonChart('canvas-comparison-chart', this.modelMetrics);
  }

  /**
   * Scans a given URL string through the extraction & ML inference pipeline
   */
  handleScan(inputUrl = null) {
    const rawUrl = (inputUrl || document.getElementById('url-input')?.value || '').trim();
    if (!rawUrl) return;

    try {
      // 1. Extract 15 features
      const extraction = FeatureExtractor.extractFeatures(rawUrl);
      const scaledVector = this.scaler.transformVector(extraction.vector);

      // 2. Model Inferences
      const lrProb = this.models.logisticRegression.predictProbability(scaledVector);
      const nbProb = this.models.naiveBayes.predictProbability(scaledVector);
      const dtProb = this.models.decisionTree.predictProbability(extraction.vector);
      const rfProb = this.models.randomForest.predictProbability(extraction.vector);

      // Ensemble weighted risk score
      const ensembleProb = (lrProb * 0.3 + nbProb * 0.2 + dtProb * 0.2 + rfProb * 0.3);

      this.currentScanResult = {
        url: rawUrl,
        extraction,
        ensembleProb,
        modelProbs: {
          'Logistic Regression': lrProb,
          'Naive Bayes': nbProb,
          'Decision Tree': dtProb,
          'Random Forest': rfProb
        }
      };

      // 3. Render Scanner Output
      this.renderScanVerdict(this.currentScanResult);
      Visualizer.drawRiskGauge('canvas-risk-gauge', ensembleProb);
      this.renderConsensusBadges(this.currentScanResult.modelProbs);
      Visualizer.drawFeatureContribution('xai-container', extraction.featureDetails, ensembleProb);
      this.renderFeatureTable(extraction.featureDetails);

    } catch (err) {
      alert(`Could not analyze URL: ${err.message}`);
      console.error(err);
    }
  }

  /**
   * Renders the prominent Verdict Banner
   */
  renderScanVerdict(scan) {
    const bannerContainer = document.getElementById('verdict-banner-container');
    if (!bannerContainer) return;

    const prob = scan.ensembleProb;
    let verdictClass = 'verdict-safe';
    let icon = '🛡️';
    let title = 'SAFE & LEGITIMATE WEBSITE';
    let desc = 'The feature extraction engine and supervised classifiers detected normal structural traits consistent with authentic websites.';

    if (prob >= 0.65) {
      verdictClass = 'verdict-phish';
      icon = '🚨';
      title = 'DANGEROUS PHISHING WEBSITE DETECTED!';
      desc = 'High confidence malicious signals matched. Do NOT enter credentials, sensitive bank details, or passwords on this site.';
    } else if (prob >= 0.40) {
      verdictClass = 'verdict-suspicious';
      icon = '⚠️';
      title = 'SUSPICIOUS / ANOMALOUS URL';
      desc = 'Certain high-risk heuristics detected (e.g. unusual length, suspicious TLD, or sensitive keywords). Exercise caution.';
    }

    bannerContainer.innerHTML = `
      <div class="verdict-banner ${verdictClass}">
        <div class="verdict-left">
          <div class="verdict-icon-badge">${icon}</div>
          <div>
            <div class="verdict-title">${title}</div>
            <div class="verdict-desc">${desc}</div>
          </div>
        </div>
        <div style="text-align: right;">
          <div style="font-size: 1.8rem; font-weight: 900; font-family: var(--font-mono);">${(prob * 100).toFixed(1)}%</div>
          <div style="font-size: 0.75rem; text-transform: uppercase; color: var(--text-muted);">Ensemble Risk Score</div>
        </div>
      </div>
    `;
  }

  /**
   * Renders consensus chips for each model
   */
  renderConsensusBadges(modelProbs) {
    const container = document.getElementById('consensus-container');
    if (!container) return;

    let html = '';
    for (const [modelName, prob] of Object.entries(modelProbs)) {
      const isPhish = prob >= 0.5;
      const tagClass = isPhish ? 'tag-phish' : 'tag-safe';
      const tagText = isPhish ? `🚨 Phishing (${Math.round(prob * 100)}%)` : `🛡️ Legit (${Math.round((1 - prob) * 100)}%)`;

      html += `
        <div class="consensus-chip">
          <span style="font-weight: 600; color: #fff; flex: 1;">${modelName}</span>
          <span class="${tagClass}">${tagText}</span>
        </div>
      `;
    }
    container.innerHTML = html;
  }

  /**
   * Renders the 15 features table
   */
  renderFeatureTable(featureDetails) {
    const tbody = document.getElementById('feature-table-body');
    if (!tbody) return;

    tbody.innerHTML = featureDetails.map(f => {
      let pillClass = 'severity-safe';
      if (f.severity === 'critical') pillClass = 'severity-critical';
      else if (f.severity === 'high') pillClass = 'severity-high';
      else if (f.severity === 'medium') pillClass = 'severity-medium';

      return `
        <tr>
          <td><b>${f.name}</b></td>
          <td><code style="color: var(--accent-sky); font-family: var(--font-mono);">${f.display}</code></td>
          <td><span style="color: var(--text-muted);">${FeatureExtractor.FEATURE_DEFINITIONS.find(def => def.name === f.name)?.normalRange || 'Standard'}</span></td>
          <td><span class="severity-pill ${pillClass}">${f.severity}</span></td>
          <td><span style="font-size: 0.8rem;">${f.explanation}</span></td>
        </tr>
      `;
    }).join('');
  }

  /**
   * Decision Tree Visualizer
   */
  renderDecisionTreeRules() {
    if (this.models.decisionTree) {
      Visualizer.renderDecisionTree(
        'tree-graph-container',
        this.models.decisionTree.getTreeStructure(),
        FeatureExtractor.FEATURE_DEFINITIONS
      );
    }
  }

  /**
   * Renders dataset explorer rows
   */
  renderDatasetTable(records) {
    const tbody = document.getElementById('dataset-table-body');
    if (!tbody) return;

    tbody.innerHTML = records.slice(0, 100).map(rec => {
      const isPhish = rec.label === 1;
      return `
        <tr>
          <td><span style="color: var(--text-muted);">${rec.id}</span></td>
          <td><span style="font-family: var(--font-mono); font-size: 0.8rem; color: #e2e8f0; word-break: break-all;">${rec.url}</span></td>
          <td><span style="font-size: 0.75rem; background: rgba(255,255,255,0.06); padding: 0.2rem 0.5rem; border-radius: 4px;">${rec.category}</span></td>
          <td>
            <span class="severity-pill ${isPhish ? 'severity-critical' : 'severity-safe'}">
              ${isPhish ? '🚨 Phishing (1)' : '🛡️ Legitimate (0)'}
            </span>
          </td>
          <td>${rec.vector[0]}</td>
          <td>${rec.vector[1] ? 'Yes' : 'No'}</td>
          <td>${rec.vector[2] ? 'Yes' : 'No'}</td>
          <td>${rec.vector[11]}</td>
          <td>
            <button class="preset-chip" style="padding: 0.2rem 0.5rem;" onclick="window.App.inspectDatasetItem('${encodeURIComponent(rec.url)}')">
              🔍 Inspect
            </button>
          </td>
        </tr>
      `;
    }).join('');
  }

  /**
   * Filters the dataset table live based on search query and category
   */
  filterDatasetTable() {
    const query = (document.getElementById('dataset-search-input')?.value || '').toLowerCase();
    const filterLabel = document.getElementById('dataset-filter-label')?.value || 'all';

    const filtered = this.dataset.records.filter(rec => {
      const matchesText = rec.url.toLowerCase().includes(query) || (rec.category || '').toLowerCase().includes(query);
      const matchesLabel = filterLabel === 'all' || rec.label.toString() === filterLabel;
      return matchesText && matchesLabel;
    });

    this.renderDatasetTable(filtered);
  }

  /**
   * Updates pill counts in Dataset explorer
   */
  updateDatasetStatsUI() {
    const total = this.dataset.records.length;
    let phish = 0, legit = 0;
    this.dataset.records.forEach(r => {
      if (r.label === 1) phish++;
      else legit++;
    });

    document.getElementById('dataset-total-pill').innerText = `Total: ${total}`;
    document.getElementById('dataset-phish-pill').innerText = `Phishing: ${phish}`;
    document.getElementById('dataset-legit-pill').innerText = `Legitimate: ${legit}`;
    document.getElementById('model-status-text').innerText = `Models Active (${total} Samples)`;
  }

  /**
   * Quick load sample from preset chips
   */
  loadSample(sampleUrl) {
    const input = document.getElementById('url-input');
    if (input) input.value = sampleUrl;
    this.handleScan(sampleUrl);
  }

  /**
   * Inspect specific dataset item in live scanner
   */
  inspectDatasetItem(encodedUrl) {
    const rawUrl = decodeURIComponent(encodedUrl);
    this.switchTab('tab-scanner');
    this.loadSample(rawUrl);
  }

  /**
   * Retrain all models with updated hyperparameters
   */
  retrainModels() {
    const btn = document.getElementById('btn-retrain');
    if (btn) {
      btn.innerHTML = '<span>⏳</span> Training Models...';
      btn.disabled = true;
    }

    setTimeout(() => {
      this.loadDatasetAndTrain();
      if (this.currentScanResult) {
        this.handleScan(this.currentScanResult.url);
      }
      if (btn) {
        btn.innerHTML = '<span>⚡</span> Train All Models';
        btn.disabled = false;
      }
    }, 150);
  }

  /**
   * Export dataset as downloadable CSV file
   */
  exportDatasetCSV() {
    const csvContent = DatasetManager.exportToCSV(this.dataset.records);
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = 'phishing_website_dataset_supervised_learning.csv';
    link.click();
  }

  /**
   * Handles user-uploaded CSV dataset
   */
  handleCSVUpload(event) {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const text = e.target.result;
        const parsed = DatasetManager.parseCSV(text);
        this.loadDatasetAndTrain(parsed);
        alert(`Successfully imported and retrained on ${parsed.length} custom samples!`);
      } catch (err) {
        alert(`Failed to parse CSV: ${err.message}`);
      }
    };
    reader.readAsText(file);
  }

  /**
   * Tab Navigation Binding
   */
  bindTabEvents() {
    const tabButtons = document.querySelectorAll('.tab-btn');
    tabButtons.forEach(btn => {
      btn.addEventListener('click', () => {
        const targetId = btn.getAttribute('data-target');
        this.switchTab(targetId);
      });
    });
  }

  switchTab(targetId) {
    this.activeTab = targetId;

    // Update buttons
    document.querySelectorAll('.tab-btn').forEach(btn => {
      const isActive = btn.getAttribute('data-target') === targetId;
      btn.classList.toggle('active', isActive);
      btn.setAttribute('aria-selected', isActive ? 'true' : 'false');
    });

    // Update panes
    document.querySelectorAll('.tab-pane').forEach(pane => {
      pane.classList.toggle('active', pane.id === targetId);
    });

    // Trigger re-render of canvases after tab pane becomes visible
    setTimeout(() => {
      if (targetId === 'tab-scanner' && this.currentScanResult) {
        Visualizer.drawRiskGauge('canvas-risk-gauge', this.currentScanResult.ensembleProb);
      } else if (targetId === 'tab-training') {
        this.renderTrainingVisualizations();
      }
    }, 50);
  }

  setupWindowResize() {
    window.addEventListener('resize', () => {
      if (this.activeTab === 'tab-scanner' && this.currentScanResult) {
        Visualizer.drawRiskGauge('canvas-risk-gauge', this.currentScanResult.ensembleProb);
      } else if (this.activeTab === 'tab-training') {
        this.renderTrainingVisualizations();
      }
    });
  }
}

// Instantiate and expose globally
document.addEventListener('DOMContentLoaded', () => {
  window.App = new PhishingDetectorApp();
  window.App.init();
});
