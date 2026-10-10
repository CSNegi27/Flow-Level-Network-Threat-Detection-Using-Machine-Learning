#!/usr/bin/env python3
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split

DATA_PATH = '/home/animesh/Desktop/network_threat_detection/dataset/network_data.csv'
SAVE_DIR  = '/home/animesh/Desktop/network_threat_detection/dataset/'

print("="*50)
print("PREPROCESSING PIPELINE")
print("="*50)

# [1] Load
df = pd.read_csv(DATA_PATH)
print(f"\n[1] Loaded: {df.shape[0]} rows, {df.shape[1]} columns")

# [2] Class distribution
print("\n[2] Class Distribution:")
print(df['label'].value_counts())

# [3] Missing values
print("\n[3] Missing Values:")
print(df.isnull().sum())

# [4] Remove duplicates
before = len(df)
df.drop_duplicates(inplace=True)
print(f"\n[4] Removed {before - len(df)} duplicates. Remaining: {len(df)}")

# [5] Replace inf values
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)
print(f"[5] After removing inf/nan: {len(df)} rows")

# [6] Features - using new flow-level features
features = [
    'flow_duration',
    'total_packets',
    'total_bytes',
    'avg_packet_size',
    'std_packet_size',
    'min_packet_size',
    'max_packet_size',
    'bytes_per_second',
    'packets_per_second',
    'syn_count',
    'ack_count',
    'fin_count',
    'rst_count',
    'syn_ratio',
    'ack_ratio',
    'unique_dst_ports',
    'protocol',
    'avg_ttl'
]

print(f"\n[6] Features used: {len(features)}")
for f in features:
    print(f"    - {f}")

X = df[features].values
y = df['label'].values

# [7] Label encoding
le = LabelEncoder()
y_encoded = le.fit_transform(y)
print(f"\n[7] Labels encoded: {list(le.classes_)}")

# [8] Feature scaling
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)
print("\n[8] Features scaled with StandardScaler")

# [9] Train/test split - stratified to handle class imbalance
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y_encoded,
    test_size=0.2,
    random_state=42,
    stratify=y_encoded
)
print(f"\n[9] Train/Test Split:")
print(f"    X_train: {X_train.shape}")
print(f"    X_test:  {X_test.shape}")

# [10] Save
np.save(SAVE_DIR + 'X_train.npy', X_train)
np.save(SAVE_DIR + 'X_test.npy',  X_test)
np.save(SAVE_DIR + 'y_train.npy', y_train)
np.save(SAVE_DIR + 'y_test.npy',  y_test)
np.save(SAVE_DIR + 'label_classes.npy', le.classes_)

# Save scaler for dashboard later
import pickle
with open(SAVE_DIR + 'scaler.pkl', 'wb') as f:
    pickle.dump(scaler, f)
with open(SAVE_DIR + 'label_encoder.pkl', 'wb') as f:
    pickle.dump(le, f)

print("\n[10] Saved:")
print(f"    X_train.npy, X_test.npy")
print(f"    y_train.npy, y_test.npy")
print(f"    label_classes.npy")
print(f"    scaler.pkl, label_encoder.pkl")

print("\n" + "="*50)
print("PREPROCESSING COMPLETE")
print("="*50)
