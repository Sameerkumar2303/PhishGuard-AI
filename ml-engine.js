/**
 * Phishing Website Detector - Machine Learning Engine
 * Client-side Supervised Learning Classifiers, Evaluators, and Data Scalers.
 */

// ==========================================
// 1. DATA PREPROCESSING & NORMALIZATION
// ==========================================
class StandardScaler {
  constructor() {
    this.means = [];
    this.stds = [];
  }

  fit(X) {
    if (!X || X.length === 0) return;
    const numFeatures = X[0].length;
    const n = X.length;
    this.means = new Array(numFeatures).fill(0);
    this.stds = new Array(numFeatures).fill(0);

    // Calculate means
    for (let i = 0; i < n; i++) {
      for (let j = 0; j < numFeatures; j++) {
        this.means[j] += X[i][j];
      }
    }
    for (let j = 0; j < numFeatures; j++) {
      this.means[j] /= n;
    }

    // Calculate standard deviations
    for (let i = 0; i < n; i++) {
      for (let j = 0; j < numFeatures; j++) {
        const diff = X[i][j] - this.means[j];
        this.stds[j] += diff * diff;
      }
    }
    for (let j = 0; j < numFeatures; j++) {
      const variance = this.stds[j] / n;
      this.stds[j] = Math.sqrt(variance) || 1e-6; // prevent division by zero
    }
  }

  transform(X) {
    return X.map(row => 
      row.map((val, j) => (val - this.means[j]) / (this.stds[j] || 1))
    );
  }

  transformVector(vector) {
    return vector.map((val, j) => (val - (this.means[j] || 0)) / (this.stds[j] || 1));
  }
}

// ==========================================
// 2. LOGISTIC REGRESSION CLASSIFIER
// ==========================================
class LogisticRegressionModel {
  constructor(config = {}) {
    this.name = 'Logistic Regression';
    this.type = 'Linear Probabilistic Classifier';
    this.learningRate = config.learningRate || 0.05;
    this.epochs = config.epochs || 150;
    this.l2Lambda = config.l2Lambda || 0.001; // regularization
    this.weights = [];
    this.bias = 0;
    this.lossHistory = [];
    this.accuracyHistory = [];
    this.isTrained = false;
  }

  static sigmoid(z) {
    if (z > 30) return 1;
    if (z < -30) return 0;
    return 1 / (1 + Math.exp(-z));
  }

  fit(X, y, onEpochCallback = null) {
    const m = X.length;
    const n = X[0].length;
    this.weights = new Array(n).fill(0).map(() => (Math.random() - 0.5) * 0.1);
    this.bias = 0;
    this.lossHistory = [];
    this.accuracyHistory = [];

    for (let epoch = 0; epoch < this.epochs; epoch++) {
      const dw = new Array(n).fill(0);
      let db = 0;
      let totalLoss = 0;
      let correct = 0;

      for (let i = 0; i < m; i++) {
        const xi = X[i];
        const yi = y[i];

        // Linear combination: z = w·x + b
        let z = this.bias;
        for (let j = 0; j < n; j++) {
          z += this.weights[j] * xi[j];
        }

        const yHat = LogisticRegressionModel.sigmoid(z);
        const error = yHat - yi;

        // Gradients accumulation
        for (let j = 0; j < n; j++) {
          dw[j] += error * xi[j];
        }
        db += error;

        // Binary Cross-Entropy Loss
        const clampedYHat = Math.max(1e-15, Math.min(1 - 1e-15, yHat));
        totalLoss += -(yi * Math.log(clampedYHat) + (1 - yi) * Math.log(1 - clampedYHat));

        const pred = yHat >= 0.5 ? 1 : 0;
        if (pred === yi) correct++;
      }

      // Update parameters with L2 regularization
      for (let j = 0; j < n; j++) {
        const grad = (dw[j] / m) + (this.l2Lambda * this.weights[j]);
        this.weights[j] -= this.learningRate * grad;
      }
      this.bias -= this.learningRate * (db / m);

      const epochLoss = totalLoss / m;
      const epochAcc = (correct / m) * 100;
      this.lossHistory.push(parseFloat(epochLoss.toFixed(4)));
      this.accuracyHistory.push(parseFloat(epochAcc.toFixed(2)));

      if (onEpochCallback && (epoch % 10 === 0 || epoch === this.epochs - 1)) {
        onEpochCallback(epoch + 1, epochLoss, epochAcc);
      }
    }

    this.isTrained = true;
    return {
      finalLoss: this.lossHistory[this.lossHistory.length - 1],
      finalAcc: this.accuracyHistory[this.accuracyHistory.length - 1]
    };
  }

  predictProbability(x) {
    let z = this.bias;
    for (let j = 0; j < x.length; j++) {
      z += (this.weights[j] || 0) * x[j];
    }
    return LogisticRegressionModel.sigmoid(z);
  }

  predict(x, threshold = 0.5) {
    return this.predictProbability(x) >= threshold ? 1 : 0;
  }

  getFeatureImportances() {
    return this.weights.map((w, idx) => ({
      featureIndex: idx,
      weight: Math.abs(w),
      rawWeight: w
    }));
  }
}

// ==========================================
// 3. GAUSSIAN NAIVE BAYES CLASSIFIER
// ==========================================
class NaiveBayesModel {
  constructor() {
    this.name = 'Naive Bayes';
    this.type = 'Probabilistic Bayesian Classifier';
    this.classes = [0, 1];
    this.priors = {};
    this.stats = {}; // mean and var for each feature per class
    this.isTrained = false;
  }

  fit(X, y) {
    const m = X.length;
    const n = X[0].length;
    this.priors = {};
    this.stats = {};

    this.classes.forEach(c => {
      const classIndices = [];
      for (let i = 0; i < m; i++) {
        if (y[i] === c) classIndices.push(i);
      }
      const count = classIndices.length;
      this.priors[c] = count / m;

      this.stats[c] = [];
      for (let j = 0; j < n; j++) {
        let sum = 0;
        for (const idx of classIndices) {
          sum += X[idx][j];
        }
        const mean = sum / (count || 1);

        let sumSqDiff = 0;
        for (const idx of classIndices) {
          const diff = X[idx][j] - mean;
          sumSqDiff += diff * diff;
        }
        const variance = (sumSqDiff / (count || 1)) + 1e-4; // smoothing variance

        this.stats[c].push({ mean, variance });
      }
    });

    this.isTrained = true;
  }

  static calculateGaussianProbability(x, mean, variance) {
    const exponent = Math.exp(-Math.pow(x - mean, 2) / (2 * variance));
    return (1 / Math.sqrt(2 * Math.PI * variance)) * exponent;
  }

  predictLogPosterior(x) {
    const logPosteriors = {};
    this.classes.forEach(c => {
      let logProb = Math.log(this.priors[c] || 1e-6);
      for (let j = 0; j < x.length; j++) {
        const { mean, variance } = this.stats[c][j];
        const prob = Math.max(1e-12, NaiveBayesModel.calculateGaussianProbability(x[j], mean, variance));
        logProb += Math.log(prob);
      }
      logPosteriors[c] = logProb;
    });
    return logPosteriors;
  }

  predictProbability(x) {
    const logs = this.predictLogPosterior(x);
    // Softmax normalization for 2 classes: 0 and 1
    const log0 = logs[0];
    const log1 = logs[1];
    const maxLog = Math.max(log0, log1);
    const exp0 = Math.exp(log0 - maxLog);
    const exp1 = Math.exp(log1 - maxLog);
    const prob1 = exp1 / (exp0 + exp1);
    return Math.min(0.999, Math.max(0.001, prob1));
  }

  predict(x, threshold = 0.5) {
    return this.predictProbability(x) >= threshold ? 1 : 0;
  }
}

// ==========================================
// 4. DECISION TREE CLASSIFIER
// ==========================================
class DecisionTreeNode {
  constructor(options = {}) {
    this.featureIndex = options.featureIndex ?? null;
    this.threshold = options.threshold ?? null;
    this.left = options.left ?? null;
    this.right = options.right ?? null;
    this.isLeaf = options.isLeaf ?? false;
    this.predictedClass = options.predictedClass ?? null;
    this.probability = options.probability ?? 0;
    this.samples = options.samples ?? 0;
    this.classCounts = options.classCounts ?? [0, 0];
    this.gini = options.gini ?? 0;
  }
}

class DecisionTreeModel {
  constructor(config = {}) {
    this.name = 'Decision Tree';
    this.type = 'Non-linear Tree Rule Classifier';
    this.maxDepth = config.maxDepth || 5;
    this.minSamplesSplit = config.minSamplesSplit || 4;
    this.root = null;
    this.featureNames = config.featureNames || [];
    this.isTrained = false;
  }

  static calculateGini(y) {
    if (y.length === 0) return 0;
    let count0 = 0;
    let count1 = 0;
    for (let i = 0; i < y.length; i++) {
      if (y[i] === 1) count1++;
      else count0++;
    }
    const p0 = count0 / y.length;
    const p1 = count1 / y.length;
    return 1 - (p0 * p0 + p1 * p1);
  }

  fit(X, y, featureSubset = null) {
    this.root = this.buildTree(X, y, 0, featureSubset);
    this.isTrained = true;
  }

  buildTree(X, y, depth, featureSubset = null) {
    const numSamples = X.length;
    const numFeatures = X[0].length;
    let count0 = 0;
    let count1 = 0;
    for (let i = 0; i < numSamples; i++) {
      if (y[i] === 1) count1++;
      else count0++;
    }

    const currentGini = DecisionTreeModel.calculateGini(y);
    const predictedClass = count1 >= count0 ? 1 : 0;
    const prob1 = numSamples > 0 ? (count1 / numSamples) : 0;

    // Stopping criteria: max depth reached, pure node, or not enough samples
    if (
      depth >= this.maxDepth || 
      currentGini === 0 || 
      numSamples < this.minSamplesSplit
    ) {
      return new DecisionTreeNode({
        isLeaf: true,
        predictedClass,
        probability: prob1,
        samples: numSamples,
        classCounts: [count0, count1],
        gini: parseFloat(currentGini.toFixed(3))
      });
    }

    // Determine features to consider (all or random subspace)
    let featuresToTest = [];
    if (featureSubset && featureSubset.length > 0) {
      featuresToTest = featureSubset;
    } else {
      for (let j = 0; j < numFeatures; j++) featuresToTest.push(j);
    }

    let bestGain = -1;
    let bestSplit = null;

    for (const featureIndex of featuresToTest) {
      // Find candidate thresholds
      const values = X.map(row => row[featureIndex]);
      const uniqueValues = Array.from(new Set(values)).sort((a, b) => a - b);

      for (let i = 0; i < uniqueValues.length - 1; i++) {
        const threshold = (uniqueValues[i] + uniqueValues[i + 1]) / 2;

        const leftX = [], leftY = [];
        const rightX = [], rightY = [];

        for (let k = 0; k < numSamples; k++) {
          if (X[k][featureIndex] <= threshold) {
            leftX.push(X[k]);
            leftY.push(y[k]);
          } else {
            rightX.push(X[k]);
            rightY.push(y[k]);
          }
        }

        if (leftY.length === 0 || rightY.length === 0) continue;

        const leftGini = DecisionTreeModel.calculateGini(leftY);
        const rightGini = DecisionTreeModel.calculateGini(rightY);
        const weightedGini = (leftY.length / numSamples) * leftGini + (rightY.length / numSamples) * rightGini;
        const gain = currentGini - weightedGini;

        if (gain > bestGain) {
          bestGain = gain;
          bestSplit = {
            featureIndex,
            threshold,
            leftX, leftY,
            rightX, rightY
          };
        }
      }
    }

    if (!bestSplit || bestGain <= 0.001) {
      return new DecisionTreeNode({
        isLeaf: true,
        predictedClass,
        probability: prob1,
        samples: numSamples,
        classCounts: [count0, count1],
        gini: parseFloat(currentGini.toFixed(3))
      });
    }

    const leftNode = this.buildTree(bestSplit.leftX, bestSplit.leftY, depth + 1, featureSubset);
    const rightNode = this.buildTree(bestSplit.rightX, bestSplit.rightY, depth + 1, featureSubset);

    return new DecisionTreeNode({
      featureIndex: bestSplit.featureIndex,
      threshold: bestSplit.threshold,
      left: leftNode,
      right: rightNode,
      isLeaf: false,
      predictedClass,
      probability: prob1,
      samples: numSamples,
      classCounts: [count0, count1],
      gini: parseFloat(currentGini.toFixed(3))
    });
  }

  predictSingle(node, x) {
    if (node.isLeaf || !node.left || !node.right) {
      return {
        predictedClass: node.predictedClass,
        probability: node.probability
      };
    }

    if (x[node.featureIndex] <= node.threshold) {
      return this.predictSingle(node.left, x);
    } else {
      return this.predictSingle(node.right, x);
    }
  }

  predictProbability(x) {
    if (!this.root) return 0.5;
    return this.predictSingle(this.root, x).probability;
  }

  predict(x, threshold = 0.5) {
    return this.predictProbability(x) >= threshold ? 1 : 0;
  }

  getTreeStructure() {
    return this.root;
  }
}

// ==========================================
// 5. RANDOM FOREST ENSEMBLE CLASSIFIER
// ==========================================
class RandomForestModel {
  constructor(config = {}) {
    this.name = 'Random Forest';
    this.type = 'Ensemble Bagging Classifier';
    this.numTrees = config.numTrees || 10;
    this.maxDepth = config.maxDepth || 6;
    this.minSamplesSplit = config.minSamplesSplit || 3;
    this.trees = [];
    this.featureNames = config.featureNames || [];
    this.isTrained = false;
  }

  fit(X, y) {
    const numSamples = X.length;
    const numFeatures = X[0].length;
    const numSubspaceFeatures = Math.max(2, Math.floor(Math.sqrt(numFeatures)) + 1);
    this.trees = [];

    for (let t = 0; t < this.numTrees; t++) {
      // Bootstrap sampling (sampling with replacement)
      const bootX = [];
      const bootY = [];
      for (let i = 0; i < numSamples; i++) {
        const randomIndex = Math.floor(Math.random() * numSamples);
        bootX.push(X[randomIndex]);
        bootY.push(y[randomIndex]);
      }

      // Random feature subset selection
      const featureIndices = [];
      while (featureIndices.length < numSubspaceFeatures) {
        const randF = Math.floor(Math.random() * numFeatures);
        if (!featureIndices.includes(randF)) {
          featureIndices.push(randF);
        }
      }

      const tree = new DecisionTreeModel({
        maxDepth: this.maxDepth,
        minSamplesSplit: this.minSamplesSplit,
        featureNames: this.featureNames
      });

      tree.fit(bootX, bootY, featureIndices);
      this.trees.push(tree);
    }

    this.isTrained = true;
  }

  predictProbability(x) {
    if (this.trees.length === 0) return 0.5;
    let sumProb = 0;
    for (const tree of this.trees) {
      sumProb += tree.predictProbability(x);
    }
    return sumProb / this.trees.length;
  }

  predict(x, threshold = 0.5) {
    return this.predictProbability(x) >= threshold ? 1 : 0;
  }
}

// ==========================================
// 6. METRICS & PERFORMANCE EVALUATION
// ==========================================
class MetricsEvaluator {
  /**
   * Calculates comprehensive classification metrics:
   * Accuracy, Precision, Recall, Specificity, F1-Score, Confusion Matrix
   */
  static evaluate(yTrue, yPred, yProbs = null) {
    const n = yTrue.length;
    let tp = 0; // True Positive (Phishing correctly identified)
    let tn = 0; // True Negative (Legitimate correctly identified)
    let fp = 0; // False Positive (Legitimate mistakenly flagged as phishing)
    let fn = 0; // False Negative (Phishing missed as legitimate)

    for (let i = 0; i < n; i++) {
      const actual = yTrue[i];
      const predicted = yPred[i];

      if (actual === 1 && predicted === 1) tp++;
      else if (actual === 0 && predicted === 0) tn++;
      else if (actual === 0 && predicted === 1) fp++;
      else if (actual === 1 && predicted === 0) fn++;
    }

    const accuracy = n > 0 ? (tp + tn) / n : 0;
    const precision = (tp + fp) > 0 ? tp / (tp + fp) : 0;
    const recall = (tp + fn) > 0 ? tp / (tp + fn) : 0;
    const specificity = (tn + fp) > 0 ? tn / (tn + fp) : 0;
    const f1Score = (precision + recall) > 0 ? 2 * (precision * recall) / (precision + recall) : 0;

    let rocCurve = [];
    let auc = 0;
    if (yProbs && yProbs.length === n) {
      const rocData = this.calculateRoc(yTrue, yProbs);
      rocCurve = rocData.points;
      auc = rocData.auc;
    }

    return {
      totalSamples: n,
      confusionMatrix: { tp, tn, fp, fn },
      accuracy: parseFloat((accuracy * 100).toFixed(2)),
      precision: parseFloat((precision * 100).toFixed(2)),
      recall: parseFloat((recall * 100).toFixed(2)),
      specificity: parseFloat((specificity * 100).toFixed(2)),
      f1Score: parseFloat((f1Score * 100).toFixed(2)),
      auc: parseFloat(auc.toFixed(3)),
      rocCurve
    };
  }

  /**
   * Computes ROC Curve points (FPR vs TPR) and AUC via Trapezoidal Rule
   */
  static calculateRoc(yTrue, yProbs) {
    const thresholds = [];
    for (let t = 0; t <= 1.0; t += 0.02) {
      thresholds.push(parseFloat(t.toFixed(2)));
    }
    thresholds.push(1.01); // ensure threshold 1 is covered

    const points = [];
    let totalP = 0;
    let totalN = 0;
    for (let i = 0; i < yTrue.length; i++) {
      if (yTrue[i] === 1) totalP++;
      else totalN++;
    }

    for (const thresh of thresholds) {
      let tp = 0;
      let fp = 0;
      for (let i = 0; i < yTrue.length; i++) {
        const pred = yProbs[i] >= thresh ? 1 : 0;
        if (pred === 1 && yTrue[i] === 1) tp++;
        if (pred === 1 && yTrue[i] === 0) fp++;
      }

      const tpr = totalP > 0 ? tp / totalP : 0; // True Positive Rate
      const fpr = totalN > 0 ? fp / totalN : 0; // False Positive Rate
      points.push({ threshold: thresh, fpr, tpr });
    }

    // Sort by FPR ascending, then TPR
    points.sort((a, b) => a.fpr - b.fpr || a.tpr - b.tpr);

    // Calculate AUC using Trapezoidal Rule
    let auc = 0;
    for (let i = 1; i < points.length; i++) {
      const deltaFpr = points[i].fpr - points[i - 1].fpr;
      const avgTpr = (points[i].tpr + points[i - 1].tpr) / 2;
      auc += deltaFpr * avgTpr;
    }

    // Ensure AUC within [0, 1]
    auc = Math.min(1.0, Math.max(0.5, Math.abs(auc)));

    return { points, auc };
  }

  /**
   * Train/Test Split helper with stratification
   */
  static trainTestSplit(X, y, rawRecords, testRatio = 0.25) {
    const class0Indices = [];
    const class1Indices = [];

    for (let i = 0; i < y.length; i++) {
      if (y[i] === 1) class1Indices.push(i);
      else class0Indices.push(i);
    }

    // Fisher-Yates shuffle
    const shuffle = arr => {
      for (let i = arr.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [arr[i], arr[j]] = [arr[j], arr[i]];
      }
    };

    shuffle(class0Indices);
    shuffle(class1Indices);

    const testCount0 = Math.floor(class0Indices.length * testRatio);
    const testCount1 = Math.floor(class1Indices.length * testRatio);

    const testIndices = [
      ...class0Indices.slice(0, testCount0),
      ...class1Indices.slice(0, testCount1)
    ];

    const trainIndices = [
      ...class0Indices.slice(testCount0),
      ...class1Indices.slice(testCount1)
    ];

    shuffle(testIndices);
    shuffle(trainIndices);

    return {
      train: {
        X: trainIndices.map(i => X[i]),
        y: trainIndices.map(i => y[i]),
        records: trainIndices.map(i => rawRecords[i])
      },
      test: {
        X: testIndices.map(i => X[i]),
        y: testIndices.map(i => y[i]),
        records: testIndices.map(i => rawRecords[i])
      }
    };
  }
}

// Support browser global or module export
if (typeof window !== 'undefined') {
  window.StandardScaler = StandardScaler;
  window.LogisticRegressionModel = LogisticRegressionModel;
  window.NaiveBayesModel = NaiveBayesModel;
  window.DecisionTreeModel = DecisionTreeModel;
  window.RandomForestModel = RandomForestModel;
  window.MetricsEvaluator = MetricsEvaluator;
}
