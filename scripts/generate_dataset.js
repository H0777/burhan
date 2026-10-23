const fs = require('fs');
const path = require('path');

const dataDir = path.join(__dirname, '..', 'ai-engine', 'app', 'data');
const modelDir = path.join(__dirname, '..', 'ai-engine', 'app', 'models', 'pretrained');

if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
if (!fs.existsSync(modelDir)) fs.mkdirSync(modelDir, { recursive: true });

const csvPath = path.join(dataDir, 'training_data.csv');
const modelPath = path.join(modelDir, 'fraud_model.pkl');

let csv = 'tx_id,amount,sender_daily_volume,sender_daily_count,is_after_hours,threshold_ratio,is_fraud_label\n';

for (let i = 1; i <= 1000; i++) {
  const r = Math.random();
  let amount, vol, count, after, label;
  if (r < 0.80) {
    amount = (10 + Math.random() * 4500).toFixed(2);
    vol = (parseFloat(amount) + Math.random() * 15000).toFixed(2);
    count = Math.floor(1 + Math.random() * 8);
    after = Math.random() < 0.05 ? 1 : 0;
    label = 0;
  } else if (r < 0.88) {
    // Smurfing
    amount = (8800 + Math.random() * 1150).toFixed(2);
    vol = (parseFloat(amount) + Math.random() * 25000).toFixed(2);
    count = Math.floor(3 + Math.random() * 10);
    after = Math.random() < 0.20 ? 1 : 0;
    label = 1;
  } else if (r < 0.93) {
    // After hours
    amount = (3000 + Math.random() * 15000).toFixed(2);
    vol = (parseFloat(amount) + Math.random() * 40000).toFixed(2);
    count = Math.floor(2 + Math.random() * 10);
    after = 1;
    label = 1;
  } else if (r < 0.97) {
    // Burst
    amount = (1500 + Math.random() * 7500).toFixed(2);
    vol = (parseFloat(amount) * 22).toFixed(2);
    count = Math.floor(21 + Math.random() * 15);
    after = Math.random() < 0.5 ? 1 : 0;
    label = 1;
  } else {
    // Layering
    amount = (25000 + Math.random() * 70000).toFixed(2);
    vol = (parseFloat(amount) + 30000).toFixed(2);
    count = Math.floor(1 + Math.random() * 5);
    after = Math.random() < 0.5 ? 1 : 0;
    label = 1;
  }
  const ratio = (parseFloat(amount) / 10000.0).toFixed(4);
  csv += `${i},${amount},${vol},${count},${after},${ratio},${label}\n`;
}

fs.writeFileSync(csvPath, csv, 'utf8');
console.log('[SUCCESS] Generated training_data.csv with 1000 rows at', csvPath);
console.log('[NOTE] To train real verifiable model artifacts, run: node scripts/run-python.js research/run_experiments.py');

