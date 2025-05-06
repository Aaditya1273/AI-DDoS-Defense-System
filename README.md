# AI-Powered DDoS Detection System

A real-time DDoS attack detection system using machine learning and network traffic analysis.

## Features

- Real-time network traffic monitoring
- Multiple ML models for attack detection (LSTM, XGBoost, Random Forest)
- Detection of various DDoS attack types:
  - SYN Flood
  - UDP Flood
  - ICMP Flood
  - HTTP Flood
- Real-time system monitoring
- Web-based dashboard
- Attack logging and analysis

## Prerequisites

- Python 3.8+
- MongoDB
- Redis
- Network interface with promiscuous mode support
- Administrative privileges for packet capture

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd ddos-detection-system
```

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

3. Install MongoDB and Redis:
- MongoDB: https://www.mongodb.com/docs/manual/installation/
- Redis: https://redis.io/download

4. Create a `.env` file in the project root:
```env
MONGODB_URI=mongodb://localhost:27017/
REDIS_HOST=localhost
REDIS_PORT=6379
```

## Usage

1. Train the models (requires training data):
```bash
python train_models.py
```

2. Start the detection system:
```bash
python ddos_detector.py
```

3. Open the web dashboard:
- Open `index.html` in your web browser
- The dashboard will automatically connect to the backend

## System Architecture

- Frontend: HTML, CSS, JavaScript with Chart.js
- Backend: Python with Flask and SocketIO
- ML Models: TensorFlow, XGBoost, Scikit-learn
- Data Storage: MongoDB for attack logs, Redis for real-time data
- Network Analysis: Scapy and PyShark

## Security Considerations

- Run with appropriate permissions for packet capture
- Keep the system updated with latest security patches
- Monitor system resources
- Regularly update ML models with new attack patterns

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

MIT License 