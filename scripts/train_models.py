#!/usr/bin/env python3
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')  # No display needed
import matplotlib.pyplot as plt
import seaborn as sns
import pickle
import os

from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.utils.class_weight import compute_sample_weight
from sklearn.metrics import (
    accuracy_score, classification_report,
    confusion_matrix
)
from xgboost import XGBClassifier

DATASET_DIR = '/home/animesh/Desktop/network_threat_detection/dataset/'
RESULTS_DIR = '/home/animesh/Desktop/network_threat_detection/results/'
os.makedirs(RESULTS_DIR, exist_ok=True)

print("="*55)
print("MODEL TRAINING PIPELINE")
print("="*55)

# Load data
X_train = np.load(DATASET_DIR + 'X_train.npy')
X_test  = np.load(DATASET_DIR + 'X_test.npy')
y_train = np.load(DATASET_DIR + 'y_train.npy')
y_test  = np.load(DATASET_DIR + 'y_test.npy')
classes = np.load(DATASET_DIR + 'label_classes.npy', allow_pickle=True)
np.save(DATASET_DIR + 'X_test.npy', X_test)
np.save(DATASET_DIR + 'y_test.npy', y_test)

print(f"\nTraining samples : {X_train.shape[0]}")
print(f"Test samples     : {X_test.shape[0]}")
print(f"Features         : {X_train.shape[1]}")
print(f"Classes          : {list(classes)}")

# Handle class imbalance with sample weights
sample_weights = compute_sample_weight(class_weight='balanced', y=y_train)

# Define models
models = {
    'Decision Tree': DecisionTreeClassifier(
        max_depth=20,
        min_samples_split=10,
        class_weight='balanced',
        random_state=42
    ),
    'Random Forest': RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        class_weight='balanced',
        n_jobs=-1,
        random_state=42
    ),
    'KNN': KNeighborsClassifier(
        n_neighbors=5,
        n_jobs=-1
    ),
    'XGBoost': XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        use_label_encoder=False,
        eval_metric='mlogloss',
        n_jobs=-1,
        random_state=42
    )
}

results = {}
trained_models = {}

print("\n" + "="*55)
for name, model in models.items():
    print(f"\nTraining: {name} ...")

    # KNN doesn't support class_weight, use sample_weight where possible
    try:
        if name == 'KNN':
            model.fit(X_train, y_train)
        elif name == 'XGBoost':
            model.fit(X_train, y_train, sample_weight=sample_weights)
        else:
            model.fit(X_train, y_train)
    except Exception as e:
        print(f"  ERROR: {e}")
        continue

    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    results[name] = acc
    trained_models[name] = (model, y_pred)

    print(f"  Accuracy: {acc*100:.2f}%")
    print(f"\n  Classification Report:")
    print(classification_report(y_test, y_pred, target_names=classes))
    print("-"*55)

# Save all models
print("\nSaving models...")
for name, (model, _) in trained_models.items():
    fname = name.lower().replace(' ', '_') + '_model.pkl'
    with open(DATASET_DIR + fname, 'wb') as f:
        pickle.dump(model, f)
    print(f"  Saved: {fname}")

# ── Plot 1: Accuracy Comparison ──────────────────────────
fig, ax = plt.subplots(figsize=(9, 5))
names = list(results.keys())
accs  = [v * 100 for v in results.values()]
colors = ['#e74c3c' if a < 80 else '#2ecc71' for a in accs]
bars = ax.bar(names, accs, color=colors, edgecolor='black', width=0.5)
ax.set_ylim(0, 110)
ax.set_ylabel('Accuracy (%)', fontsize=12)
ax.set_title('Model Accuracy Comparison', fontsize=14, fontweight='bold')
for bar, acc in zip(bars, accs):
    ax.text(bar.get_x() + bar.get_width()/2,
            bar.get_height() + 1.5,
            f'{acc:.2f}%', ha='center', va='bottom', fontweight='bold')
ax.axhline(y=90, color='blue', linestyle='--', alpha=0.4, label='90% target')
ax.legend()
plt.tight_layout()
plt.savefig(RESULTS_DIR + 'accuracy_comparison.png', dpi=150)
plt.close()
print("\nSaved: accuracy_comparison.png")

# ── Plot 2: Confusion Matrix for best model ───────────────
best_name = max(results, key=results.get)
best_pred = trained_models[best_name][1]
cm = confusion_matrix(y_test, best_pred)
fig, ax = plt.subplots(figsize=(8, 6))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=classes, yticklabels=classes, ax=ax)
ax.set_title(f'Confusion Matrix — {best_name} ({results[best_name]*100:.2f}%)',
             fontsize=13, fontweight='bold')
ax.set_ylabel('Actual', fontsize=11)
ax.set_xlabel('Predicted', fontsize=11)
plt.tight_layout()
plt.savefig(RESULTS_DIR + 'confusion_matrix.png', dpi=150)
plt.close()
print("Saved: confusion_matrix.png")

# ── Plot 3: Feature Importance (Random Forest) ────────────
if 'Random Forest' in trained_models:
    rf_model = trained_models['Random Forest'][0]
    feature_names = [
        'flow_duration', 'total_packets', 'total_bytes',
        'avg_packet_size', 'std_packet_size', 'min_packet_size',
        'max_packet_size', 'bytes_per_second', 'packets_per_second',
        'syn_count', 'ack_count', 'fin_count', 'rst_count',
        'syn_ratio', 'ack_ratio', 'unique_dst_ports',
        'protocol', 'avg_ttl'
    ]
    importances = rf_model.feature_importances_
    indices = np.argsort(importances)[::-1]

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.bar(range(len(importances)),
           importances[indices],
           color='steelblue', edgecolor='black')
    ax.set_xticks(range(len(importances)))
    ax.set_xticklabels([feature_names[i] for i in indices],
                       rotation=45, ha='right', fontsize=9)
    ax.set_title('Feature Importance — Random Forest',
                 fontsize=13, fontweight='bold')
    ax.set_ylabel('Importance Score')
    plt.tight_layout()
    plt.savefig(RESULTS_DIR + 'feature_importance.png', dpi=150)
    plt.close()
    print("Saved: feature_importance.png")

# ── Final Summary ─────────────────────────────────────────
print("\n" + "="*55)
print("FINAL RESULTS SUMMARY")
print("="*55)
for name, acc in sorted(results.items(), key=lambda x: -x[1]):
    bar = "█" * int(acc * 40)
    print(f"  {name:<18} {acc*100:6.2f}%  {bar}")

best_acc = max(results.values())
print(f"\n  Best Model : {best_name}")
print(f"  Accuracy   : {best_acc*100:.2f}%")
print("\n" + "="*55)
print("TRAINING COMPLETE")
print("="*55)
