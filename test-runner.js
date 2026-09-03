const FeatureExtractor = require('./feature-extractor.js');
const { StandardScaler, LogisticRegressionModel, NaiveBayesModel, DecisionTreeModel, RandomForestModel, MetricsEvaluator } = require('./ml-engine.js');
const DatasetManager = require('./dataset.js');

console.log('Testing Feature Extractor...');
const feat = FeatureExtractor.extractFeatures('http://paypal-security-update-verify.com/login/auth.php');
console.log('Features extracted successfully:', feat.vector.length, 'features');

console.log('Testing Dataset Manager...');
const ds = DatasetManager.loadProcessedDataset();
console.log(`Loaded dataset: ${ds.records.length} records (${ds.y.filter(l => l === 1).length} phish, ${ds.y.filter(l => l === 0).length} legit)`);

console.log('Testing Train/Test Split...');
const split = MetricsEvaluator.trainTestSplit(ds.X, ds.y, ds.records, 0.25);
console.log(`Train set: ${split.train.X.length}, Test set: ${split.test.X.length}`);

console.log('Testing StandardScaler...');
const scaler = new StandardScaler();
scaler.fit(split.train.X);
const trainXScaled = scaler.transform(split.train.X);
const testXScaled = scaler.transform(split.test.X);

console.log('Testing Logistic Regression...');
const lr = new LogisticRegressionModel({ learningRate: 0.05, epochs: 100 });
lr.fit(trainXScaled, split.train.y);
const lrProbs = testXScaled.map(x => lr.predictProbability(x));
const lrPreds = lrProbs.map(p => p >= 0.5 ? 1 : 0);
const lrMetrics = MetricsEvaluator.evaluate(split.test.y, lrPreds, lrProbs);
console.log('Logistic Regression Accuracy:', lrMetrics.accuracy + '%', 'AUC:', lrMetrics.auc);

console.log('Testing Naive Bayes...');
const nb = new NaiveBayesModel();
nb.fit(trainXScaled, split.train.y);
const nbProbs = testXScaled.map(x => nb.predictProbability(x));
const nbPreds = nbProbs.map(p => p >= 0.5 ? 1 : 0);
const nbMetrics = MetricsEvaluator.evaluate(split.test.y, nbPreds, nbProbs);
console.log('Naive Bayes Accuracy:', nbMetrics.accuracy + '%', 'AUC:', nbMetrics.auc);

console.log('Testing Decision Tree...');
const dt = new DecisionTreeModel({ maxDepth: 5 });
dt.fit(split.train.X, split.train.y);
const dtProbs = split.test.X.map(x => dt.predictProbability(x));
const dtPreds = dtProbs.map(p => p >= 0.5 ? 1 : 0);
const dtMetrics = MetricsEvaluator.evaluate(split.test.y, dtPreds, dtProbs);
console.log('Decision Tree Accuracy:', dtMetrics.accuracy + '%', 'AUC:', dtMetrics.auc);

console.log('Testing Random Forest...');
const rf = new RandomForestModel({ numTrees: 10, maxDepth: 6 });
rf.fit(split.train.X, split.train.y);
const rfProbs = split.test.X.map(x => rf.predictProbability(x));
const rfPreds = rfProbs.map(p => p >= 0.5 ? 1 : 0);
const rfMetrics = MetricsEvaluator.evaluate(split.test.y, rfPreds, rfProbs);
console.log('Random Forest Accuracy:', rfMetrics.accuracy + '%', 'AUC:', rfMetrics.auc);

console.log('All tests passed successfully!');
