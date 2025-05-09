import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import xgboost as xgb
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout
import joblib
import os

def create_lstm_model(input_shape):
    model = Sequential([
        LSTM(64, input_shape=input_shape, return_sequences=True),
        Dropout(0.2),
        LSTM(32),
        Dropout(0.2),
        Dense(16, activation='relu'),
        Dense(1, activation='sigmoid')
    ])
    
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    return model

def create_xgb_model():
    return xgb.XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42
    )

def create_rf_model():
    return RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42
    )

def prepare_data(data):
    # Convert categorical features to numerical
    data['protocol'] = data['protocol'].astype('category').cat.codes
    data['flags'] = data['flags'].astype('category').cat.codes
    
    # Normalize numerical features
    numerical_features = ['packet_size', 'src_port', 'dst_port']
    for feature in numerical_features:
        if feature in data.columns:
            data[feature] = (data[feature] - data[feature].mean()) / data[feature].std()
    
    return data

def train_models():
    # Create models directory if it doesn't exist
    os.makedirs('models', exist_ok=True)
    
    # Load and prepare training data
    # Note: You need to provide your own training data
    # This is just a placeholder
    data = pd.read_csv('training_data.csv')
    data = prepare_data(data)
    
    # Split data
    X = data.drop('is_attack', axis=1)
    y = data['is_attack']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Train LSTM model
    X_train_lstm = X_train.values.reshape(X_train.shape[0], 1, X_train.shape[1])
    X_test_lstm = X_test.values.reshape(X_test.shape[0], 1, X_test.shape[1])
    
    lstm_model = create_lstm_model((1, X_train.shape[1]))
    lstm_model.fit(X_train_lstm, y_train, epochs=10, batch_size=32, validation_split=0.2)
    lstm_model.save('models/lstm_model.h5')
    
    # Train XGBoost model
    xgb_model = create_xgb_model()
    xgb_model.fit(X_train, y_train)
    joblib.dump(xgb_model, 'models/xgb_model.joblib')
    
    # Train Random Forest model
    rf_model = create_rf_model()
    rf_model.fit(X_train, y_train)
    joblib.dump(rf_model, 'models/rf_model.joblib')
    
    # Evaluate models
    lstm_score = lstm_model.evaluate(X_test_lstm, y_test)[1]
    xgb_score = xgb_model.score(X_test, y_test)
    rf_score = rf_model.score(X_test, y_test)
    
    print(f"LSTM Accuracy: {lstm_score:.4f}")
    print(f"XGBoost Accuracy: {xgb_score:.4f}")
    print(f"Random Forest Accuracy: {rf_score:.4f}")

if __name__ == '__main__':
    train_models() 