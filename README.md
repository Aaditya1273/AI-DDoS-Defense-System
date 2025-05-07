# 🧠💥 AI-Powered DDoS Detection System

A real-time 🕒 DDoS attack detection system using machine learning 🤖 and network traffic analysis 🌐.

---

## 🚀 Features

* 📡 Real-time network traffic monitoring
* 🧠 Multiple ML models for attack detection:
  * LSTM 🔁
  * XGBoost 📊
  * Random Forest 🌳
* 🚨 Detection of various DDoS attack types:
  * 🔗 SYN Flood
  * 🌊 UDP Flood
  * ⚡ ICMP Flood
  * 🌐 HTTP Flood
* 📈 Real-time system monitoring and CPU usage tracking
* 🖥️ Web-based dashboard with interactive controls
* 🗃️ Attack logging and analysis
* 🧪 Test mode for controlled attack simulation
* 🔄 Reset functionality to clear statistics
* 🔍 Support for capturing real network traffic

---

## 📦 Prerequisites

* 🐍 Python 3.8+ 
* 🍃 MongoDB
* 🔁 Redis
* 🧰 Network interface with promiscuous mode support


---

## ⚙️ Installation

1. 📥 Clone the repository:

```bash
git clone <repository-url>
cd AI-DDoS-Defense-System
```

2. 📦 Install Python dependencies:

```bash
pip install -r requirements.txt
```

3. 🛠️ Install MongoDB and Redis:

* 🍃 MongoDB: [https://www.mongodb.com/docs/manual/installation/](https://www.mongodb.com/docs/manual/installation/)
* 🔁 Redis: [https://redis.io/download](https://redis.io/download)

4. 📝 Create a `.env` file in the project root:

```env
MONGODB_URI=mongodb://localhost:27017/
REDIS_HOST=localhost
REDIS_PORT=6379
```

---

## 🧪 Usage

1. 🎯 Train the models (requires training data):

```bash
python train_models.py
```

2. 🚨 Start the detection system:

```bash
python main.py
```

3. 🌐 Access the web dashboard:

* The dashboard will be automatically served at http://localhost:5000
* Dashboard features:
  * Real-time traffic visualization
  * Attack detection indicators
  * System resource monitoring
  * Test mode controls
  * Reset functionality

---

## 🔄 Operation Modes

### Real Traffic Mode
Captures and analyzes actual network traffic for DDoS detection. Requires appropriate network interface access and permissions.

### Test Mode
Generates simulated attack traffic for testing and demonstration purposes without affecting network operations.

---

## 🏗️ System Architecture

* 🎨 Frontend: HTML, CSS, JavaScript with Chart.js 📊
* 🔧 Backend: Python with Flask 🌶️ and SocketIO ⚡
* 🤖 ML Models: TensorFlow 🧠, XGBoost 📈, Scikit-learn 📘
* 💾 Data Storage: MongoDB 📚, Redis 🧮
* 🔍 Network Analysis: Scapy 🕷️ and PyShark 🦈

---

## 🔐 Security Considerations

* 📛 Run with proper permissions
* 🛡️ Keep software up-to-date
* 🧠 Monitor system resource usage
* 🆕 Regularly retrain ML models
* ⚠️ Be aware of system resource consumption during detection operations

---

## 🛠️ Troubleshooting

* If encountering "Layer not found" errors in test mode, check packet generation configuration
* For CPU usage reporting discrepancies, the system includes a calibration offset
* If statistics persist after stopping tests, use the Reset button to clear them

---