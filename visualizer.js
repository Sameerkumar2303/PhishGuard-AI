/**
 * Phishing Website Detector - Interactive Visualizer & Canvas Engine
 * High-performance, retina-crisp rendering for charts, gauges, matrices, and trees.
 */

class Visualizer {
  /**
   * Helper to set canvas DPI scaling for ultra-sharp rendering on Retina screens
   */
  static setupCanvas(canvas) {
    if (!canvas) return null;
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    
    // Set responsive CSS width/height to prevent exponential scaling 
    // without hardcoding pixels or breaking hidden tabs
    if (!canvas.style.width) {
      canvas.style.width = '100%';
      canvas.style.height = '100%';
    }

    const rect = canvas.getBoundingClientRect();
    
    // Set internal resolution scaled by device pixel ratio
    if (canvas.width !== Math.floor(rect.width * dpr) && rect.width > 0) {
      canvas.width = rect.width * dpr;
      canvas.height = rect.height * dpr;
    }
    
    ctx.resetTransform?.();
    ctx.scale(dpr, dpr);
    return { ctx, width: rect.width || canvas.width / dpr, height: rect.height || canvas.height / dpr };
  }

  // ==========================================
  // 1. RISK GAUGE METER (0 - 100%)
  // ==========================================
  static drawRiskGauge(canvasId, probability) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const setup = this.setupCanvas(canvas);
    if (!setup) return;
    const { ctx, width, height } = setup;

    ctx.clearRect(0, 0, width, height);

    const centerX = width / 2;
    const centerY = height * 0.78;
    const radius = Math.min(width * 0.38, height * 0.65);
    const lineWidth = Math.max(12, radius * 0.16);

    const startAngle = Math.PI * 0.85;
    const endAngle = Math.PI * 2.15;
    const totalAngle = endAngle - startAngle;

    // Background track
    ctx.beginPath();
    ctx.arc(centerX, centerY, radius, startAngle, endAngle, false);
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.08)';
    ctx.lineWidth = lineWidth;
    ctx.lineCap = 'round';
    ctx.stroke();

    // Foreground dynamic gradient track
    const currentAngle = startAngle + (totalAngle * Math.min(1, Math.max(0, probability)));

    const gradient = ctx.createLinearGradient(centerX - radius, centerY, centerX + radius, centerY);
    gradient.addColorStop(0, '#10b981');   // Safe Green
    gradient.addColorStop(0.45, '#06b6d4'); // Cyan
    gradient.addColorStop(0.7, '#f59e0b');  // Warning Amber
    gradient.addColorStop(1, '#ef4444');    // Danger Red

    if (probability > 0.01) {
      ctx.beginPath();
      ctx.arc(centerX, centerY, radius, startAngle, currentAngle, false);
      ctx.strokeStyle = gradient;
      ctx.lineWidth = lineWidth;
      ctx.lineCap = 'round';
      ctx.shadowColor = probability > 0.6 ? 'rgba(239, 68, 68, 0.4)' : 'rgba(16, 185, 129, 0.4)';
      ctx.shadowBlur = 15;
      ctx.stroke();
      ctx.shadowBlur = 0; // reset
    }

    // Needle indicator
    const needleLength = radius * 0.85;
    const needleAngle = currentAngle;
    const needleX = centerX + Math.cos(needleAngle) * needleLength;
    const needleY = centerY + Math.sin(needleAngle) * needleLength;

    // Needle line
    ctx.beginPath();
    ctx.moveTo(centerX, centerY);
    ctx.lineTo(needleX, needleY);
    ctx.strokeStyle = '#ffffff';
    ctx.lineWidth = 3;
    ctx.lineCap = 'round';
    ctx.shadowColor = 'rgba(0, 0, 0, 0.5)';
    ctx.shadowBlur = 6;
    ctx.stroke();
    ctx.shadowBlur = 0;

    // Center pivot cap
    ctx.beginPath();
    ctx.arc(centerX, centerY, 8, 0, Math.PI * 2);
    ctx.fillStyle = '#38bdf8';
    ctx.fill();
    ctx.strokeStyle = '#ffffff';
    ctx.lineWidth = 2;
    ctx.stroke();

    // Percentage text
    const percentage = Math.round(probability * 100);
    ctx.font = 'bold 28px "Inter", "Segoe UI", sans-serif';
    ctx.fillStyle = probability >= 0.7 ? '#ef4444' : (probability >= 0.4 ? '#f59e0b' : '#10b981');
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(`${percentage}%`, centerX, centerY - radius * 0.35);

    ctx.font = '600 12px "Inter", sans-serif';
    ctx.fillStyle = 'rgba(255, 255, 255, 0.55)';
    ctx.fillText('PHISHING PROBABILITY', centerX, centerY - radius * 0.35 + 24);
  }

  // ==========================================
  // 2. TRAINING LOSS & ACCURACY CONVERGENCE CHART
  // ==========================================
  static drawLossChart(canvasId, lossHistory, accHistory) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const setup = this.setupCanvas(canvas);
    if (!setup) return;
    const { ctx, width, height } = setup;

    ctx.clearRect(0, 0, width, height);

    const padding = { top: 30, right: 50, bottom: 40, left: 55 };
    const chartW = width - padding.left - padding.right;
    const chartH = height - padding.top - padding.bottom;

    if (!lossHistory || lossHistory.length === 0) {
      ctx.font = '14px "Inter", sans-serif';
      ctx.fillStyle = 'rgba(255,255,255,0.4)';
      ctx.textAlign = 'center';
      ctx.fillText('No training run performed yet. Click "Train Models" to start.', width / 2, height / 2);
      return;
    }

    const n = lossHistory.length;
    const maxLoss = Math.max(...lossHistory, 1.0);
    const minLoss = Math.min(...lossHistory, 0.0);

    // Draw grid & axes
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.06)';
    ctx.lineWidth = 1;

    for (let i = 0; i <= 4; i++) {
      const y = padding.top + (chartH / 4) * i;
      ctx.beginPath();
      ctx.moveTo(padding.left, y);
      ctx.lineTo(width - padding.right, y);
      ctx.stroke();

      // Left axis label (Loss)
      const lossVal = (maxLoss - (maxLoss - minLoss) * (i / 4)).toFixed(2);
      ctx.font = '11px monospace';
      ctx.fillStyle = '#f43f5e';
      ctx.textAlign = 'right';
      ctx.fillText(lossVal, padding.left - 8, y + 4);

      // Right axis label (Accuracy %)
      const accVal = (100 - 25 * i).toFixed(0) + '%';
      ctx.fillStyle = '#10b981';
      ctx.textAlign = 'left';
      ctx.fillText(accVal, width - padding.right + 8, y + 4);
    }

    // X-axis epoch labels
    ctx.fillStyle = 'rgba(255, 255, 255, 0.5)';
    ctx.textAlign = 'center';
    ctx.font = '11px sans-serif';
    ctx.fillText('Epoch 1', padding.left, height - 12);
    ctx.fillText(`Epoch ${Math.round(n / 2)}`, padding.left + chartW / 2, height - 12);
    ctx.fillText(`Epoch ${n}`, width - padding.right, height - 12);

    // Plot Loss Curve (Crimson / Pink)
    ctx.beginPath();
    for (let i = 0; i < n; i++) {
      const x = padding.left + (i / (n - 1 || 1)) * chartW;
      const normalizedLoss = (lossHistory[i] - minLoss) / (maxLoss - minLoss || 1);
      const y = padding.top + chartH - (normalizedLoss * chartH);
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    }
    ctx.strokeStyle = '#f43f5e';
    ctx.lineWidth = 2.5;
    ctx.shadowColor = 'rgba(244, 63, 94, 0.4)';
    ctx.shadowBlur = 8;
    ctx.stroke();
    ctx.shadowBlur = 0;

    // Plot Accuracy Curve (Emerald)
    if (accHistory && accHistory.length === n) {
      ctx.beginPath();
      for (let i = 0; i < n; i++) {
        const x = padding.left + (i / (n - 1 || 1)) * chartW;
        const normalizedAcc = accHistory[i] / 100;
        const y = padding.top + chartH - (normalizedAcc * chartH);
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      }
      ctx.strokeStyle = '#10b981';
      ctx.lineWidth = 2.5;
      ctx.shadowColor = 'rgba(16, 185, 129, 0.4)';
      ctx.shadowBlur = 8;
      ctx.stroke();
      ctx.shadowBlur = 0;
    }

    // Chart Legend
    ctx.font = '600 12px "Inter", sans-serif';
    ctx.fillStyle = '#f43f5e';
    ctx.textAlign = 'left';
    ctx.fillText('● Binary Cross-Entropy Loss', padding.left + 10, padding.top - 12);

    ctx.fillStyle = '#10b981';
    ctx.fillText('● Training Accuracy (%)', padding.left + 210, padding.top - 12);
  }

  // ==========================================
  // 3. INTERACTIVE CONFUSION MATRIX
  // ==========================================
  static drawConfusionMatrix(containerId, cm) {
    const container = document.getElementById(containerId);
    if (!container) return;

    const { tp, tn, fp, fn } = cm;
    const total = tp + tn + fp + fn || 1;

    const tpPct = ((tp / total) * 100).toFixed(1);
    const tnPct = ((tn / total) * 100).toFixed(1);
    const fpPct = ((fp / total) * 100).toFixed(1);
    const fnPct = ((fn / total) * 100).toFixed(1);

    container.innerHTML = `
      <div class="cm-grid">
        <div class="cm-corner"></div>
        <div class="cm-header-col">Predicted: Legitimate (0)</div>
        <div class="cm-header-col">Predicted: Phishing (1)</div>

        <div class="cm-header-row">Actual: Legitimate (0)</div>
        <div class="cm-cell cm-cell-success">
          <div class="cm-tag">True Negative (TN)</div>
          <div class="cm-count">${tn}</div>
          <div class="cm-pct">${tnPct}%</div>
          <div class="cm-subtext">Legitimate correctly recognized</div>
        </div>
        <div class="cm-cell cm-cell-danger">
          <div class="cm-tag">False Positive (FP)</div>
          <div class="cm-count">${fp}</div>
          <div class="cm-pct">${fpPct}%</div>
          <div class="cm-subtext">False Alarm (Safe flagged as Phish)</div>
        </div>

        <div class="cm-header-row">Actual: Phishing (1)</div>
        <div class="cm-cell cm-cell-danger">
          <div class="cm-tag">False Negative (FN)</div>
          <div class="cm-count">${fn}</div>
          <div class="cm-pct">${fnPct}%</div>
          <div class="cm-subtext">Critical Miss (Phish slipped through)</div>
        </div>
        <div class="cm-cell cm-cell-success">
          <div class="cm-tag">True Positive (TP)</div>
          <div class="cm-count">${tp}</div>
          <div class="cm-pct">${tpPct}%</div>
          <div class="cm-subtext">Phishing caught successfully</div>
        </div>
      </div>
    `;
  }

  // ==========================================
  // 4. ROC CURVE (RECEIVER OPERATING CHARACTERISTIC)
  // ==========================================
  static drawRocCurve(canvasId, rocPoints, auc) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const setup = this.setupCanvas(canvas);
    if (!setup) return;
    const { ctx, width, height } = setup;

    ctx.clearRect(0, 0, width, height);

    const padding = { top: 30, right: 30, bottom: 45, left: 55 };
    const chartW = width - padding.left - padding.right;
    const chartH = height - padding.top - padding.bottom;

    if (!rocPoints || rocPoints.length === 0) {
      ctx.font = '14px "Inter", sans-serif';
      ctx.fillStyle = 'rgba(255,255,255,0.4)';
      ctx.textAlign = 'center';
      ctx.fillText('Train a model with probability outputs to view ROC curve.', width / 2, height / 2);
      return;
    }

    // Grid
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.06)';
    ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
      const y = padding.top + (chartH / 4) * i;
      const x = padding.left + (chartW / 4) * i;

      ctx.beginPath();
      ctx.moveTo(padding.left, y);
      ctx.lineTo(width - padding.right, y);
      ctx.stroke();

      ctx.beginPath();
      ctx.moveTo(x, padding.top);
      ctx.lineTo(x, height - padding.bottom);
      ctx.stroke();

      // Labels
      const val = (1.0 - i * 0.25).toFixed(2);
      ctx.font = '11px monospace';
      ctx.fillStyle = 'rgba(255, 255, 255, 0.45)';
      ctx.textAlign = 'right';
      ctx.fillText(val, padding.left - 8, y + 4);

      const xVal = (i * 0.25).toFixed(2);
      ctx.textAlign = 'center';
      ctx.fillText(xVal, x, height - padding.bottom + 18);
    }

    // Random Chance Diagonal Baseline (0,0 -> 1,1)
    ctx.beginPath();
    ctx.setLineDash([4, 4]);
    ctx.moveTo(padding.left, height - padding.bottom);
    ctx.lineTo(width - padding.right, padding.top);
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.3)';
    ctx.lineWidth = 1.5;
    ctx.stroke();
    ctx.setLineDash([]); // reset dash

    // Fill ROC Area under curve
    ctx.beginPath();
    ctx.moveTo(padding.left, height - padding.bottom);
    for (const pt of rocPoints) {
      const x = padding.left + pt.fpr * chartW;
      const y = padding.top + chartH - (pt.tpr * chartH);
      ctx.lineTo(x, y);
    }
    ctx.lineTo(width - padding.right, height - padding.bottom);
    ctx.closePath();
    const areaGrad = ctx.createLinearGradient(0, padding.top, 0, height - padding.bottom);
    areaGrad.addColorStop(0, 'rgba(6, 182, 212, 0.25)');
    areaGrad.addColorStop(1, 'rgba(6, 182, 212, 0.01)');
    ctx.fillStyle = areaGrad;
    ctx.fill();

    // Stroke ROC Line
    ctx.beginPath();
    for (let i = 0; i < rocPoints.length; i++) {
      const pt = rocPoints[i];
      const x = padding.left + pt.fpr * chartW;
      const y = padding.top + chartH - (pt.tpr * chartH);
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    }
    ctx.strokeStyle = '#06b6d4';
    ctx.lineWidth = 3;
    ctx.shadowColor = 'rgba(6, 182, 212, 0.5)';
    ctx.shadowBlur = 10;
    ctx.stroke();
    ctx.shadowBlur = 0;

    // Axis titles
    ctx.font = '600 12px "Inter", sans-serif';
    ctx.fillStyle = 'rgba(255, 255, 255, 0.7)';
    ctx.textAlign = 'center';
    ctx.fillText('False Positive Rate (FPR)', padding.left + chartW / 2, height - 8);

    ctx.save();
    ctx.translate(16, padding.top + chartH / 2);
    ctx.rotate(-Math.PI / 2);
    ctx.fillText('True Positive Rate (TPR / Recall)', 0, 0);
    ctx.restore();

    // AUC Badge
    ctx.fillStyle = '#0f172a';
    ctx.strokeStyle = '#06b6d4';
    ctx.lineWidth = 1.5;
    const badgeX = width - padding.right - 120;
    const badgeY = height - padding.bottom - 45;
    ctx.beginPath();
    ctx.roundRect?.(badgeX, badgeY, 110, 32, 6) || ctx.rect(badgeX, badgeY, 110, 32);
    ctx.fill();
    ctx.stroke();

    ctx.font = 'bold 12px monospace';
    ctx.fillStyle = '#38bdf8';
    ctx.textAlign = 'center';
    ctx.fillText(`AUC = ${auc.toFixed(3)}`, badgeX + 55, badgeY + 20);
  }

  // ==========================================
  // 5. MULTI-MODEL COMPARISON BAR CHART
  // ==========================================
  static drawModelComparisonChart(canvasId, comparisonData) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const setup = this.setupCanvas(canvas);
    if (!setup) return;
    const { ctx, width, height } = setup;

    ctx.clearRect(0, 0, width, height);

    const padding = { top: 40, right: 30, bottom: 45, left: 45 };
    const chartW = width - padding.left - padding.right;
    const chartH = height - padding.top - padding.bottom;

    if (!comparisonData || comparisonData.length === 0) return;

    const numModels = comparisonData.length;
    const metrics = ['accuracy', 'precision', 'recall', 'f1Score'];
    const metricLabels = ['Accuracy', 'Precision', 'Recall', 'F1 Score'];
    const metricColors = ['#10b981', '#06b6d4', '#f59e0b', '#a855f7'];

    // Grid
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.06)';
    ctx.lineWidth = 1;
    for (let i = 0; i <= 5; i++) {
      const y = padding.top + (chartH / 5) * i;
      ctx.beginPath();
      ctx.moveTo(padding.left, y);
      ctx.lineTo(width - padding.right, y);
      ctx.stroke();

      const val = 100 - i * 20;
      ctx.font = '11px monospace';
      ctx.fillStyle = 'rgba(255, 255, 255, 0.4)';
      ctx.textAlign = 'right';
      ctx.fillText(`${val}%`, padding.left - 6, y + 4);
    }

    const groupWidth = chartW / numModels;
    const barWidth = Math.min(22, (groupWidth * 0.75) / metrics.length);

    comparisonData.forEach((item, mIdx) => {
      const groupCenterX = padding.left + groupWidth * mIdx + groupWidth / 2;
      const startX = groupCenterX - ((metrics.length * barWidth) / 2);

      // Model Name
      ctx.font = '600 12px "Inter", sans-serif';
      ctx.fillStyle = '#ffffff';
      ctx.textAlign = 'center';
      ctx.fillText(item.name, groupCenterX, height - 15);

      metrics.forEach((metricKey, kIdx) => {
        const val = item.metrics[metricKey] || 0;
        const barH = (val / 100) * chartH;
        const x = startX + kIdx * barWidth;
        const y = padding.top + chartH - barH;

        ctx.fillStyle = metricColors[kIdx];
        ctx.beginPath();
        ctx.roundRect?.(x, y, barWidth - 3, barH, [4, 4, 0, 0]) || ctx.rect(x, y, barWidth - 3, barH);
        ctx.fill();
      });
    });

    // Legend
    ctx.font = '500 11px "Inter", sans-serif';
    metricLabels.forEach((label, idx) => {
      const legX = padding.left + idx * 105;
      ctx.fillStyle = metricColors[idx];
      ctx.beginPath();
      ctx.arc(legX + 6, padding.top - 18, 5, 0, Math.PI * 2);
      ctx.fill();

      ctx.fillStyle = 'rgba(255, 255, 255, 0.75)';
      ctx.textAlign = 'left';
      ctx.fillText(label, legX + 16, padding.top - 14);
    });
  }

  // ==========================================
  // 6. EXPLAINABLE AI (XAI) FEATURE CONTRIBUTION
  // ==========================================
  static drawFeatureContribution(containerId, featureDetails, probability) {
    const container = document.getElementById(containerId);
    if (!container) return;

    if (!featureDetails || featureDetails.length === 0) {
      container.innerHTML = '<div class="empty-state">Scan a URL to view feature contribution explainability.</div>';
      return;
    }

    // Sort by suspicious severity and heuristic impact
    const sortedFeatures = [...featureDetails].sort((a, b) => {
      const weightA = a.isSuspicious ? (a.severity === 'critical' ? 3 : (a.severity === 'high' ? 2 : 1)) : 0;
      const weightB = b.isSuspicious ? (b.severity === 'critical' ? 3 : (b.severity === 'high' ? 2 : 1)) : 0;
      return weightB - weightA;
    });

    let html = `
      <div class="xai-summary-card ${probability >= 0.5 ? 'xai-phish' : 'xai-safe'}">
        <div class="xai-summary-header">
          <span class="xai-badge">${probability >= 0.5 ? '⚠️ High Malicious Signals Detected' : '🛡️ Normal Safety Profile'}</span>
          <span class="xai-score">${(probability * 100).toFixed(1)}% Phishing Risk</span>
        </div>
        <p class="xai-summary-text">
          ${probability >= 0.5 
            ? 'The Supervised Classifier flagged strong risk indicators such as credential lures, high entropy, or domain spoofing heuristics.' 
            : 'Extracted lexical and structural markers align closely with legitimate domain distributions.'}
        </p>
      </div>
      <div class="xai-bars-list">
    `;

    for (const f of sortedFeatures.slice(0, 8)) {
      const isRed = f.isSuspicious;
      const barColor = isRed ? (f.severity === 'critical' ? '#ef4444' : '#f97316') : '#10b981';
      const widthPct = isRed ? (f.severity === 'critical' ? 95 : (f.severity === 'high' ? 75 : 50)) : 30;

      html += `
        <div class="xai-bar-item">
          <div class="xai-bar-info">
            <span class="xai-feature-name">${f.name}</span>
            <span class="xai-feature-val" style="color: ${barColor}">${f.display}</span>
          </div>
          <div class="xai-track">
            <div class="xai-fill" style="width: ${widthPct}%; background-color: ${barColor};"></div>
          </div>
          <div class="xai-desc">${f.explanation}</div>
        </div>
      `;
    }

    html += `</div>`;
    container.innerHTML = html;
  }

  // ==========================================
  // 7. INTERACTIVE DECISION TREE VISUALIZER
  // ==========================================
  static renderDecisionTree(containerId, rootNode, featureDefinitions) {
    const container = document.getElementById(containerId);
    if (!container) return;

    if (!rootNode) {
      container.innerHTML = '<div class="empty-state">Train the Decision Tree model to view the interactive hierarchical tree structure.</div>';
      return;
    }

    const buildNodeHtml = (node, depth = 0) => {
      if (!node) return '';

      if (node.isLeaf) {
        const isPhish = node.predictedClass === 1;
        const confidence = ((isPhish ? node.probability : (1 - node.probability)) * 100).toFixed(1);
        return `
          <div class="dt-leaf ${isPhish ? 'dt-leaf-phish' : 'dt-leaf-safe'}">
            <div class="dt-badge">${isPhish ? '🚨 PHISHING' : '🛡️ LEGITIMATE'}</div>
            <div class="dt-meta">Samples: <b>${node.samples}</b> | Conf: <b>${confidence}%</b></div>
            <div class="dt-meta">Class [Legit, Phish]: [${node.classCounts[0]}, ${node.classCounts[1]}]</div>
          </div>
        `;
      }

      const featureDef = featureDefinitions[node.featureIndex] || { name: `Feature ${node.featureIndex}` };
      const threshFormatted = Number.isInteger(node.threshold) ? node.threshold : parseFloat(node.threshold).toFixed(2);

      return `
        <div class="dt-node-wrapper">
          <div class="dt-node">
            <div class="dt-condition">
              <b>${featureDef.name}</b> &le; <code>${threshFormatted}</code>
            </div>
            <div class="dt-meta">Gini: ${node.gini} | Samples: ${node.samples}</div>
          </div>
          <div class="dt-branches">
            <div class="dt-branch dt-branch-left">
              <span class="dt-branch-label">True (Yes)</span>
              ${buildNodeHtml(node.left, depth + 1)}
            </div>
            <div class="dt-branch dt-branch-right">
              <span class="dt-branch-label">False (No)</span>
              ${buildNodeHtml(node.right, depth + 1)}
            </div>
          </div>
        </div>
      `;
    };

    container.innerHTML = `
      <div class="dt-tree-container">
        <div class="dt-root-title">Decision Tree Rules Structure</div>
        ${buildNodeHtml(rootNode, 0)}
      </div>
    `;
  }
}

// Support browser global or module export
if (typeof window !== 'undefined') {
  window.Visualizer = Visualizer;
}
if (typeof module !== 'undefined' && module.exports) {
  module.exports = Visualizer;
}
