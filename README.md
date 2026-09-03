# 🛡️ Phishing Website Detector — Supervised Machine Learning Project

An end-to-end, interactive, and visually stunning Supervised Learning web application built using pure **HTML5, Modern Vanilla CSS, and JavaScript**.

This project extracts **15 lexical, structural, and heuristic features** from raw website URLs and classifies them as **Legitimate** or **Phishing** in real time across four distinct supervised learning algorithms.

---

## 🌟 Key Features

1. **Live URL Scanner & Heuristic Feature Extractor**:
   - Parses any user-input URL or 1-click test preset.
   - Extracts 15 real-world cyber threat signals (URL length, IP address hostname, shortened links, `@` obfuscation, subdomain depth, HTTPS token spoofing, sensitive keywords, non-standard ports, Shannon character entropy, and more).
   - Real-time animated **Radial Risk Gauge** and dynamic **Verdict Banner**.

2. **Four Supervised Learning Classifiers (Pure JavaScript)**:
   - **Logistic Regression**: Gradient Descent with L2 regularization, sigmoid activation, and epoch-by-epoch binary cross-entropy loss tracking.
   - **Gaussian Naive Bayes**: Prior/posterior probabilities and continuous Gaussian distribution likelihood estimation.
   - **Decision Tree**: Binary recursive feature splitting based on Gini Impurity minimization.
   - **Random Forest Ensemble**: Bagging ensemble combining multiple randomized decision trees with majority voting.

3. **Explainable AI (XAI)**:
   - Feature Contribution Waterfall breakdown explaining *why* a particular URL was flagged as malicious or safe.

4. **Interactive Training & Evaluation Dashboard**:
   - Customizable hyperparameters (Train/Test Split ratio, Learning Rate $\alpha$, Iteration Epochs, Tree Max Depth).
   - Real-time **Loss & Accuracy Convergence Line Chart**.
   - Interactive **Confusion Matrix** (True Positives, True Negatives, False Positives, False Negatives).
   - **Receiver Operating Characteristic (ROC) Curve** with automated Area Under Curve ($AUC$) calculation.
   - Grouped Comparative Performance Bar Chart across all 4 algorithms.

5. **Dataset Explorer & Custom CSV Manager**:
   - 130+ preloaded ground-truth labeled benchmark URLs across Banking, E-Commerce, Social Media, Crypto, Delivery, and Government domains.
   - Full search & filter capabilities.
   - **Export Dataset to CSV** and **Import Custom CSV** file support.

6. **Interactive Decision Tree Visualizer**:
   - Collapsible hierarchical visualization of decision tree if-else rules, showing splitting thresholds, Gini values, and class sample distributions.

7. **Comprehensive Supervised Learning Theory Guide**:
   - Mathematical formulas, pipeline stages, and cybersecurity significance.

---

## 🚀 How to Run the Project

No Node.js build step or complex server installation is required.

### Method 1: Direct Browser Launch
1. Open the folder:
   `C:\Users\LENOVO\Desktop\supervised learning project`
2. Double-click **`index.html`** in any modern web browser (Google Chrome, Microsoft Edge, Firefox, Safari).

### Method 2: Local Static Server (Optional)
If you prefer running via a local server:
```powershell
# Using Python
cd "C:\Users\LENOVO\Desktop\supervised learning project"
python -m http.server 8000

# Or using npx serve
npx serve .
```
Then open `http://localhost:8000` in your browser.

---

## 📂 Project Structure

```
supervised learning project/
├── index.html            # Main single-page application structure & 5 tabs
├── styles.css            # Cyber-AI dark theme, glassmorphism & responsive CSS
├── feature-extractor.js  # 15 URL heuristic & lexical feature extraction engine
├── ml-engine.js          # Pure JS Logistic Regression, Naive Bayes, Decision Tree, Random Forest & Metrics
├── dataset.js            # Curated 130+ benchmark labeled dataset & CSV parser
├── visualizer.js         # Canvas charts (Loss, ROC, Comparison, Risk Gauge, Decision Tree)
├── app.js                # App lifecycle controller, event bindings, and live scanner
└── README.md             # Project documentation and guide
```

---

## 🧮 Implemented Supervised Learning Formulas

- **Sigmoid Function**:
  $$\sigma(z) = \frac{1}{1 + e^{-z}}$$

- **Binary Cross-Entropy Loss**:
  $$J(\mathbf{w}, b) = -\frac{1}{m} \sum_{i=1}^m \left[ y^{(i)} \log(\hat{y}^{(i)}) + (1 - y^{(i)}) \log(1 - \hat{y}^{(i)}) \right]$$

- **Gini Impurity**:
  $$\text{Gini}(S) = 1 - \sum_{i=0}^1 p_i^2$$

- **Gaussian Likelihood (Naive Bayes)**:
  $$P(x_i \mid y) = \frac{1}{\sqrt{2\pi\sigma_y^2}} \exp\left(-\frac{(x_i - \mu_y)^2}{2\sigma_y^2}\right)$$

- **Classification Evaluation Metrics**:
  $$\text{Accuracy} = \frac{TP + TN}{TP + TN + FP + FN}$$
  $$\text{Precision} = \frac{TP}{TP + FP}, \quad \text{Recall} = \frac{TP}{TP + FN}$$
  $$F_1 = 2 \cdot \frac{\text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}$$
