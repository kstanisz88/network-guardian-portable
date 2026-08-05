#!/usr/bin/env python3
"""
Task 2: Create Inference Engine + Model Training
Train ensemble model on NSL-KDD (proxy for UNSW-NB15 features) and create inference module.
"""

import warnings

import joblib
import numpy as np
import pandas as pd

warnings.filterwarnings('ignore')

import lightgbm as lgb
import xgboost as xgb
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, f1_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

# ── 1. Load and prepare NSL-KDD data ──────────────────────────────────
print("Loading NSL-KDD 20% training set...")
# The CSV has 43 columns: 41 features + label + difficulty
# But the label is text, not numeric
df = pd.read_csv('data/NSL_KDD_20percent.csv', header=None)

# Feature names from Field Names.csv (41 features)
feature_names = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
]

# Column 41 = label (text), column 42 = difficulty (numeric)
df.columns = feature_names + ['attack_type', 'difficulty']

# Binary: normal vs attack
df['is_attack'] = (df['attack_type'] != 'normal').astype(int)

print(f"Data shape: {df.shape}")
print(f"Attack distribution:\n{df['is_attack'].value_counts()}")
print(f"Attack types: {df['attack_type'].nunique()}")
print(f"Sample attack types: {df[df['is_attack']==1]['attack_type'].unique()[:10]}")

# ── 2. Preprocessing ──────────────────────────────────────────────────
# Categorical features
cat_features = ['protocol_type', 'service', 'flag']
num_features = [c for c in feature_names if c not in cat_features]

print(f"\nNumeric features: {len(num_features)}")
print(f"Categorical features: {cat_features}")

# Encode categoricals
encoders = {}
for col in cat_features:
    le = LabelEncoder()
    df[col] = le.fit_transform(df[col].astype(str))
    encoders[col] = le

# Features and targets
X = df[feature_names].values
y_binary = df['is_attack'].values
y_multi = df['attack_type'].values

# Scale
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Save encoders and scaler
joblib.dump(scaler, 'models/scaler.pkl')
joblib.dump(encoders, 'models/label_encoders.pkl')
print("\n✅ Saved scaler.pkl and label_encoders.pkl")

# ── 3. Train/Test Split ───────────────────────────────────────────────
X_train, X_test, y_train_bin, y_test_bin = train_test_split(
    X_scaled, y_binary, test_size=0.2, random_state=42, stratify=y_binary
)
_, _, y_train_multi, y_test_multi = train_test_split(
    X_scaled, y_multi, test_size=0.2, random_state=42
)

print(f"\nTrain: {X_train.shape[0]}, Test: {X_test.shape[0]}")
print(f"Train attack distribution: {np.bincount(y_train_bin)}")
print(f"Test attack distribution: {np.bincount(y_test_bin)}")

# ── 4. Train Ensemble Models ──────────────────────────────────────────
print("\n" + "="*60)
print("TRAINING ENSEMBLE MODELS (Binary Classification)")
print("="*60)

models = {}
results = {}

# RandomForest
print("\n🌲 Training RandomForest...")
rf = RandomForestClassifier(n_estimators=200, max_depth=15, random_state=42, n_jobs=-1)
rf.fit(X_train, y_train_bin)
y_pred = rf.predict(X_test)
acc = accuracy_score(y_test_bin, y_pred)
f1 = f1_score(y_test_bin, y_pred)
models['random_forest'] = rf
results['RandomForest'] = {'accuracy': acc, 'f1': f1}
print(f"   Accuracy: {acc:.4f}, F1: {f1:.4f}")

# XGBoost
print("\n🚀 Training XGBoost...")
xgb_model = xgb.XGBClassifier(
    n_estimators=300, max_depth=6, learning_rate=0.05,
    subsample=0.8, colsample_bytree=0.8, tree_method='hist',
    random_state=42, n_jobs=-1, eval_metric='logloss'
)
xgb_model.fit(X_train, y_train_bin)
y_pred = xgb_model.predict(X_test)
acc = accuracy_score(y_test_bin, y_pred)
f1 = f1_score(y_test_bin, y_pred)
models['xgboost'] = xgb_model
results['XGBoost'] = {'accuracy': acc, 'f1': f1}
print(f"   Accuracy: {acc:.4f}, F1: {f1:.4f}")

# LightGBM
print("\n💡 Training LightGBM...")
lgb_model = lgb.LGBMClassifier(
    n_estimators=300, max_depth=-1, learning_rate=0.05,
    subsample=0.8, colsample_bytree=0.8, verbose=-1,
    random_state=42, n_jobs=-1
)
lgb_model.fit(X_train, y_train_bin)
y_pred = lgb_model.predict(X_test)
acc = accuracy_score(y_test_bin, y_pred)
f1 = f1_score(y_test_bin, y_pred)
models['lightgbm'] = lgb_model
results['LightGBM'] = {'accuracy': acc, 'f1': f1}
print(f"   Accuracy: {acc:.4f}, F1: {f1:.4f}")

# ── 5. Ensemble (Voting) ──────────────────────────────────────────────
print("\n🎯 Creating Ensemble (Soft Voting)...")
from sklearn.ensemble import VotingClassifier

ensemble = VotingClassifier(
    estimators=[
        ('rf', rf),
        ('xgb', xgb_model),
        ('lgb', lgb_model)
    ],
    voting='soft',
    weights=[1, 2, 2]  # XGB and LGBM slightly better
)
ensemble.fit(X_train, y_train_bin)
y_pred = ensemble.predict(X_test)
acc = accuracy_score(y_test_bin, y_pred)
f1 = f1_score(y_test_bin, y_pred)
models['ensemble'] = ensemble
results['Ensemble'] = {'accuracy': acc, 'f1': f1}
print(f"   Accuracy: {acc:.4f}, F1: {f1:.4f}")

# ── 6. Save Best Model ────────────────────────────────────────────────
best_model_name = max(results, key=lambda k: results[k]['f1'])
best_model = models[best_model_name.lower().replace(' ', '_')]
print(f"\n🏆 Best model: {best_model_name} (F1: {results[best_model_name]['f1']:.4f})")

joblib.dump(best_model, 'models/rf_anomaly_model.pkl')
print("✅ Saved rf_anomaly_model.pkl (ensemble)")

# Also save individual models for ensemble inference
joblib.dump(rf, 'models/rf_model.pkl')
joblib.dump(xgb_model, 'models/xgb_model.pkl')
joblib.dump(lgb_model, 'models/lgb_model.pkl')
print("✅ Saved individual models for ensemble inference")

# ── 7. Multi-class training (threat type classification) ─────────────
print("\n" + "="*60)
print("TRAINING MULTI-CLASS MODEL (Threat Type Classification)")
print("="*60)

# Use only attack samples for multi-class
attack_mask_train = y_train_bin == 1
attack_mask_test = y_test_bin == 1

if attack_mask_train.sum() > 100:
    X_train_att = X_train[attack_mask_train]
    y_train_att = y_train_multi[attack_mask_train]
    X_test_att = X_test[attack_mask_test]
    y_test_att = y_test_multi[attack_mask_test]
    
    print(f"Attack samples - Train: {len(X_train_att)}, Test: {len(X_test_att)}")
    
    rf_multi = RandomForestClassifier(n_estimators=200, max_depth=15, random_state=42, n_jobs=-1)
    rf_multi.fit(X_train_att, y_train_att)
    y_pred_att = rf_multi.predict(X_test_att)
    acc_att = accuracy_score(y_test_att, y_pred_att)
    print(f"Multi-class Accuracy: {acc_att:.4f}")
    print(classification_report(y_test_att, y_pred_att))
    
    joblib.dump(rf_multi, 'models/threat_classifier.pkl')
    print("✅ Saved threat_classifier.pkl")

# ── 8. Summary ────────────────────────────────────────────────────────
print("\n" + "="*60)
print("TRAINING SUMMARY")
print("="*60)
for name, metrics in results.items():
    print(f"  {name:<20} Acc: {metrics['accuracy']:.4f}  F1: {metrics['f1']:.4f}")

print("\n📁 Models saved to models/:")
print("   - rf_anomaly_model.pkl (binary ensemble)")
print("   - rf_model.pkl, xgb_model.pkl, lgb_model.pkl (individual)")
print("   - scaler.pkl")
print("   - label_encoders.pkl")
print("   - threat_classifier.pkl (multi-class)")

print(f"\n📊 Feature names ({len(feature_names)}): {feature_names}")

# Also save feature names for inference
joblib.dump(feature_names, 'models/feature_names.pkl')
print("✅ Saved feature_names.pkl")