#!/usr/bin/env python3
"""
Autoencoder-basierte Anomalieerkennung für Log-Dateien
Erkennt Anomalien in Log-Dateien durch Rekonstruktionsfehler
"""

import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense
from tensorflow.keras.optimizers import Adam
import re
import glob
import sys
import os
from collections import Counter
import argparse

class LogAutoencoder:
    def __init__(self, encoding_dim=16, epochs=20, batch_size=16):
        self.encoding_dim = encoding_dim
        self.epochs = epochs
        self.batch_size = batch_size
        self.autoencoder = None
        self.encoder = None
        self.decoder = None
        self.feature_names = []
        
    def preprocess_logs(self, log_files):
        """Verarbeitet Log-Dateien und extrahiert Features"""
        all_events = []
        
        # Sammle alle Events aus allen Log-Dateien
        for log_file in log_files:
            try:
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        # Extrahiere Event-Typ
                        event_type = self.extract_event_type(line)
                        all_events.append(event_type)
            except Exception as e:
                print(f"Fehler beim Lesen von {log_file}: {e}")
        
        if not all_events:
            print("Keine Events in den Log-Dateien gefunden.")
            return np.array([])
        
        # Wähle die häufigsten Ereignistypen als Features
        event_counter = Counter(all_events)
        self.feature_names = [event for event, count in event_counter.most_common(20)]
        
        # Erstelle Feature-Vektoren für jede Log-Datei
        file_features = []
        
        for log_file in log_files:
            try:
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    events = []
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        event_type = self.extract_event_type(line)
                        events.append(event_type)
                
                # Zähle Vorkommen jedes Ereignistyps in dieser Datei
                file_event_counter = Counter(events)
                feature_vector = [file_event_counter.get(event, 0) for event in self.feature_names]
                
                # Normalisiere den Vektor
                total_events = sum(feature_vector)
                if total_events > 0:
                    feature_vector = [count / total_events for count in feature_vector]
                else:
                    feature_vector = [0] * len(self.feature_names)
                
                file_features.append(feature_vector)
                
            except Exception as e:
                print(f"Fehler beim Verarbeiten von {log_file}: {e}")
                file_features.append([0] * len(self.feature_names))
        
        return np.array(file_features)
    
    def extract_event_type(self, log_line):
        """Extrahiert den Ereignistyp aus einer Log-Zeile"""
        # Vereinfachte Ereigniserkennung
        if "EVENT_EXEC" in log_line:
            return "EXEC"
        elif "EVENT_FILE" in log_line:
            return "FILE_ACCESS"
        elif "CRITICAL_FILE" in log_line:
            return "CRITICAL_FILE_ACCESS"
        elif "HEARTBEAT" in log_line:
            return "HEARTBEAT"
        elif "RATTENJAGD_START" in log_line:
            return "START"
        elif "RATTENJAGD_END" in log_line:
            return "END"
        elif "ALERT" in log_line:
            return "ALERT"
        elif "SYSTEM" in log_line:
            return "SYSTEM"
        else:
            # Extrahiere den ersten Teil der Log-Zeile
            parts = log_line.split('|')
            if len(parts) > 0:
                return parts[0].strip()[:20]  # Begrenze auf 20 Zeichen
            return "OTHER"
    
    def build_model(self, input_dim):
        """Baut den Autoencoder"""
        # Eingabe
        input_layer = Input(shape=(input_dim,))
        
        # Encoder
        encoded = Dense(32, activation='relu')(input_layer)
        encoded = Dense(self.encoding_dim, activation='relu')(encoded)
        
        # Decoder
        decoded = Dense(32, activation='relu')(encoded)
        decoded = Dense(input_dim, activation='sigmoid')(decoded)
        
        # Modelle
        self.autoencoder = Model(input_layer, decoded)
        self.encoder = Model(input_layer, encoded)
        
        # Kompiliere das Modell
        self.autoencoder.compile(optimizer=Adam(learning_rate=0.001), 
                               loss='mse')
        
        return self.autoencoder
    
    def train(self, X):
        """Trainiert den Autoencoder"""
        if X.shape[0] < 2:
            print("Nicht genug Daten zum Trainieren. Benötige mindestens 2 Log-Dateien.")
            return False
        
        input_dim = X.shape[1]
        self.build_model(input_dim)
        
        # Trainiere den Autoencoder ohne Validation Split wenn zu wenig Daten
        if X.shape[0] < 5:
            self.autoencoder.fit(X, X,
                               epochs=self.epochs,
                               batch_size=min(self.batch_size, X.shape[0]),
                               shuffle=True,
                               verbose=0)
        else:
            self.autoencoder.fit(X, X,
                               epochs=self.epochs,
                               batch_size=self.batch_size,
                               shuffle=True,
                               validation_split=0.2,
                               verbose=0)
        return True
    
    def detect_anomalies(self, X, threshold_multiplier=1.5):
        """Erkennt Anomalien basierend auf Rekonstruktionsfehlern"""
        if X.shape[0] == 0:
            return np.array([]), 0
        
        # Vorhersagen
        X_pred = self.autoencoder.predict(X, verbose=0)
        
        # Berechne Rekonstruktionsfehler (MSE)
        mse = np.mean(np.power(X - X_pred, 2), axis=1)
        
        # Setze Schwellenwert für Anomalien
        if len(mse) > 1:
            threshold = np.mean(mse) + threshold_multiplier * np.std(mse)
        else:
            threshold = mse[0] * 1.5 if len(mse) > 0 else 0
        
        return mse, threshold
    
    def analyze_files(self, log_files):
        """Analysiert eine Liste von Log-Dateien auf Anomalien"""
        if not log_files:
            print("Keine Log-Dateien gefunden.")
            return [], 0
        
        # Verarbeite Log-Dateien und extrahiere Features
        X = self.preprocess_logs(log_files)
        
        if X.shape[0] == 0:
            print("Keine Daten zum Analysieren gefunden.")
            return [], 0
        
        print(f"Verarbeite {X.shape[0]} Log-Dateien mit {X.shape[1]} Features...")
        
        # Für einzelne Dateien: Verwende Gesamtanzahl der Events als Score
        if X.shape[0] == 1:
            print("Nur eine Datei - verwende Event-Count als Score...")
            event_count = np.sum(X[0])
            scores = np.array([event_count])
            threshold = event_count * 1.5
        elif X.shape[0] >= 2:
            print("Trainiere Autoencoder...")
            if self.train(X):
                scores, threshold = self.detect_anomalies(X)
            else:
                # Fallback: Verwende Gesamtanzahl der Events als Score
                event_counts = np.sum(X, axis=1)
                scores = event_counts
                threshold = np.mean(event_counts) * 1.5
        else:
            scores = np.array([0])
            threshold = 0
        
        # Erstelle eine Liste mit Dateinamen und Scores
        results = []
        for i, log_file in enumerate(log_files):
            score = scores[i] if i < len(scores) else 0
            results.append({
                'file': log_file,
                'score': score,
                'anomaly': score > threshold
            })
        
        # Sortiere nach Score (absteigend)
        results.sort(key=lambda x: x['score'], reverse=True)
        
        return results, threshold

def main():
    parser = argparse.ArgumentParser(description='Autoencoder-basierte Anomalieerkennung in Log-Dateien')
    parser.add_argument('log_files', nargs='+', help='Log-Dateien zur Analyse')
    parser.add_argument('--encoding-dim', type=int, default=16, help='Dimension des Encodings')
    parser.add_argument('--epochs', type=int, default=20, help='Anzahl der Trainingsepochen')
    parser.add_argument('--batch-size', type=int, default=16, help='Batch-Größe')
    
    args = parser.parse_args()
    
    # Finde alle Log-Dateien (unterstützt Wildcards)
    all_log_files = []
    for pattern in args.log_files:
        if '*' in pattern or '?' in pattern:
            all_log_files.extend(glob.glob(pattern))
        else:
            all_log_files.append(pattern)
    
    # Entferne Duplikate
    all_log_files = list(set(all_log_files))
    
    if not all_log_files:
        print("Keine Log-Dateien gefunden.")
        return
    
    print(f"Analysiere {len(all_log_files)} Log-Dateien...")
    
    # Initialisiere den Autoencoder
    autoencoder = LogAutoencoder(
        encoding_dim=args.encoding_dim,
        epochs=args.epochs,
        batch_size=args.batch_size
    )
    
    # Analysiere die Dateien
    results, threshold = autoencoder.analyze_files(all_log_files)
    
    if not results:
        print("Keine Ergebnisse erhalten.")
        return
    
    # Zeige die Ergebnisse
    print("\n" + "="*60)
    print("ANOMALIE-RANKING")
    print("="*60)
    print(f"Anomalie-Schwellenwert: {threshold:.6f}")
    print(f"Feature-Vektor: {autoencoder.feature_names}")
    print("-"*60)
    
    for i, result in enumerate(results):
        rank = i + 1
        anomaly_flag = "ANOMALIE" if result['anomaly'] else "Normal "
        print(f"{rank:2d}. {anomaly_flag} [{result['score']:.6f}, {os.path.basename(result['file'])}]")
        
        # Zeige nur Top 10 oder alle wenn weniger
        if i >= 9 and len(results) > 10:
            remaining = len(results) - 10
            print(f"... und {remaining} weitere Dateien")
            break
    
    print("="*60)

if __name__ == "__main__":
    # Deaktiviere TensorFlow Logging
    os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
    tf.get_logger().setLevel('ERROR')
    
    try:
        main()
    except Exception as e:
        print(f"Fehler: {e}")
        print("Stelle sicher, dass Sie mehrere Log-Dateien für eine aussagekräftige Analyse haben.")
