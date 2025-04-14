import os
import sys
import pickle
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
import subprocess
import tempfile
import re
import tkinter as tk
from tkinter import filedialog
import json
from datetime import datetime

def extract_features_manually(pdf_path):
    """
    Extract features manually without relying on pdfid
    This is a more robust approach that doesn't depend on external tools
    """
    try:
        features = {}
        
        features['pdfsize'] = os.path.getsize(pdf_path)
        
        default_features = {
            'metadata size': 0, 'pages': 0, 'xref Length': 0, 'title characters': 0,
            'isEncrypted': 0, 'embedded files': 0, 'images': 0, 'obj': 0, 'endobj': 0,
            'stream': 0, 'endstream': 0, 'xref': 0, 'trailer': 0, 'startxref': 0,
            'pageno': 0, 'encrypt': 0, 'ObjStm': 0, 'JS': 0, 'Javascript': 0,
            'AA': 0, 'OpenAction': 0, 'Acroform': 0, 'JBIG2Decode': 0, 'RichMedia': 0,
            'launch': 0, 'EmbeddedFile': 0, 'XFA': 0, 'Colors': 0, 'text': 0, 'pdf_version': 1.4
        }
        features.update(default_features)
        
        with open(pdf_path, 'rb') as f:
            header_data = f.read(1024).decode('latin-1', errors='ignore')
            
            if '%PDF-' in header_data:
                version_match = re.search(r'%PDF-(\d+\.\d+)', header_data)
                if version_match:
                    try:
                        features['pdf_version'] = float(version_match.group(1))
                    except:
                        features['pdf_version'] = 1.4  
            
            f.seek(0)
            content = f.read().decode('latin-1', errors='ignore')
            
            features['obj'] = len(re.findall(r'\b\d+\s+\d+\s+obj\b', content))
            features['endobj'] = content.count('endobj')
            features['stream'] = content.count('stream')
            features['endstream'] = content.count('endstream')
            features['xref'] = content.count('xref')
            features['trailer'] = content.count('trailer')
            features['startxref'] = content.count('startxref')
            features['pageno'] = content.count('/Page')
            features['encrypt'] = content.count('/Encrypt')
            features['ObjStm'] = content.count('/ObjStm')
            features['JS'] = content.count('/JS')
            features['Javascript'] = content.count('/JavaScript')
            features['AA'] = content.count('/AA')
            features['OpenAction'] = content.count('/OpenAction')
            features['Acroform'] = content.count('/AcroForm')
            features['JBIG2Decode'] = content.count('/JBIG2Decode')
            features['RichMedia'] = content.count('/RichMedia')
            features['launch'] = content.count('/Launch')
            features['EmbeddedFile'] = content.count('/EmbeddedFile')
            features['XFA'] = content.count('/XFA')
            
            metadata_pattern = re.search(r'/Metadata\s+\d+\s+\d+\s+R', content)
            if metadata_pattern:
                features['metadata size'] = 1000  
            
            pages_pattern = re.search(r'/Count\s+(\d+)', content)
            if pages_pattern:
                try:
                    features['pages'] = int(pages_pattern.group(1))
                except:
                    pass
            
            features['text'] = 1 if re.search(r'/Text', content) is not None else 0
        
        features['js_javascript_interaction'] = features['JS'] * features['Javascript']
        features['pdfsize_metadata_ratio'] = features['pdfsize'] / (features['metadata size'] + 1e-6)
        features['stream_obj_ratio'] = features['stream'] / (features['obj'] + 1e-6) if features['obj'] > 0 else 0
        features['has_no_pages'] = 1 if features['pages'] == 0 else 0
        features['has_no_text'] = 1 if features['text'] == 0 else 0
        
        print("Extracted features directly from the PDF file")
        return features
        
    except Exception as e:
        print(f"Error in manual feature extraction: {e}")
        import traceback
        traceback.print_exc()
        return None

FEATURE_IMPORTANCE = {
    'text': 0.115023,
    'OpenAction': 0.101820,
    'has_no_text': 0.065119,
    'Javascript': 0.064310,
    'startxref': 0.056778,
    'pdf_version': 0.049204,
    'JS': 0.046197,
    'stream': 0.045297,
    'xref': 0.042590,
    'metadata size': 0.036893,
    'obj': 0.036469,
    'trailer': 0.031603,
    'endstream': 0.028489,
    'js_javascript_interaction': 0.025285,
    'XFA': 0.023770,
    'endobj': 0.022852,
    'images': 0.019565,
    'Acroform': 0.019357,
    'stream_obj_ratio': 0.017007,
    'embedded files': 0.015535,
    'EmbeddedFile': 0.015357,
    'pageno': 0.014767,
    'ObjStm': 0.013064,
    'has_no_pages': 0.012687,
    'pdfsize': 0.012361,
    'pdfsize_metadata_ratio': 0.009962,
    'xref Length': 0.009732,
    'launch': 0.009517,
    'Colors': 0.009123,
    'isEncrypted': 0.007527,
    'RichMedia': 0.006182,
    'title characters': 0.004165,
    'pages': 0.003579,
    'AA': 0.003345,
    'encrypt': 0.003190,
    'JBIG2Decode': 0.002270
}

def predict_pdf_malware(pdf_path, model_path=None, scaler_path=None, features_path=None):
    """
    Predict if a PDF file is malware using saved models
    
    Args:
        pdf_path: Path to the PDF file
        model_path: Path to the saved model pickle file (optional)
        scaler_path: Path to the saved scaler pickle file (optional)
        features_path: Path to the saved top features pickle file (optional)
        
    Returns:
        tuple: (prediction (0=benign, 1=malicious), probability of malicious class, extracted_features)
    """
    if model_path is None:
        model_path = 'model.pkl'
    if scaler_path is None:
        scaler_path = 'scaler.pkl'
    if features_path is None:
        features_path = "top_features.pkl"
    
    try:
        with open(model_path, 'rb') as f:
            model = pickle.load(f)
        
        with open(scaler_path, 'rb') as f:
            scaler = pickle.load(f)
        
        with open(features_path, 'rb') as f:
            top_features = pickle.load(f)
            
        print("Models loaded successfully")
    except Exception as e:
        print(f"Error loading models: {e}")
        return None, None, None
    
    extracted_features = extract_features_manually(pdf_path)
        
    if not extracted_features:
        print("Failed to extract features from PDF")
        return None, None, None
    
    df = pd.DataFrame([extracted_features])
    
    for col in df.columns:
        if col.lower() == 'javascript' and col != 'Javascript':
            df['Javascript'] = df[col]
            df = df.drop(col, axis=1)
    
    scaler_feature_names = None
    try:
        if hasattr(scaler, 'feature_names_in_'):
            scaler_feature_names = scaler.feature_names_in_
        elif hasattr(scaler, 'get_feature_names_out'):
            scaler_feature_names = scaler.get_feature_names_out()
    except:
        print("Could not determine scaler feature names, will try to proceed anyway")
    
    print("Feature names from data:")
    print(sorted(df.columns.tolist()))
    print("\nTop features expected by model:")
    print(sorted(top_features))
    
    try:
        X_raw = df.copy()
        
        model_input = pd.DataFrame()
        for feature in top_features:
            if feature in X_raw.columns:
                model_input[feature] = X_raw[feature]
            else:
                print(f"Missing feature: {feature}, adding with default value 0")
                model_input[feature] = 0
                
        X = model_input.values
    except Exception as e:
        print(f"Error preparing features: {e}")
        import traceback
        traceback.print_exc()
        return None, None, None
    
    try:
        probability = model.predict_proba(X)[0][1]  
        prediction = 1 if probability >= 0.5 else 0
        return prediction, probability, extracted_features
    except Exception as e:
        print(f"Error making prediction: {e}")
        import traceback
        traceback.print_exc()
        return None, None, None

def generate_json_report(pdf_path, prediction, probability, features):
    report = {
        "report_metadata": {
            "version": "1.0",
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "file_analyzed": os.path.basename(pdf_path),
            "file_path": pdf_path,
            "file_size_bytes": features.get("pdfsize", 0)
        },
        "analysis_result": {
            "classification": "MALICIOUS" if prediction == 1 else "BENIGN",
            "confidence": round(probability * 100, 2),
            "risk_level": "Unknown"
        },
        "feature_analysis": {
            "significant_features": [],
            "all_features": []
        }
    }
    
    if prediction == 1:
        if probability > 0.9:
            report["analysis_result"]["risk_level"] = "HIGH"
        elif probability > 0.7:
            report["analysis_result"]["risk_level"] = "MEDIUM"
        else:
            report["analysis_result"]["risk_level"] = "LOW"
    else:
        report["analysis_result"]["risk_level"] = "SAFE"
        if probability > 0.4:
            report["analysis_result"]["warning"] = "Contains some suspicious characteristics but classified as benign"
    
    feature_items = []
    for feature_name, feature_value in features.items():
        importance = FEATURE_IMPORTANCE.get(feature_name, 0)
        feature_items.append({
            "name": feature_name,
            "value": feature_value,
            "importance": importance,
            "contribution": importance * feature_value if feature_value is not None else 0
        })
    
    feature_items.sort(key=lambda x: x["contribution"], reverse=True)
    
    report["feature_analysis"]["all_features"] = feature_items
    
    report["feature_analysis"]["significant_features"] = feature_items[:10]
    
    significant_findings = []
    for feature in feature_items[:5]:
        if feature["value"] > 0 and feature["importance"] > 0.01:
            if feature["name"] == "text" and feature["value"] == 0:
                significant_findings.append(f"No text content detected (importance: {feature['importance']:.4f})")
            elif feature["name"] == "has_no_text" and feature["value"] == 1:
                significant_findings.append(f"Lack of text content is suspicious (importance: {feature['importance']:.4f})")
            elif feature["name"] in ["JS", "Javascript", "js_javascript_interaction"]:
                significant_findings.append(f"Contains JavaScript ({feature['name']}: {feature['value']}, importance: {feature['importance']:.4f})")
            elif feature["name"] == "OpenAction":
                significant_findings.append(f"Contains automatic actions (OpenAction: {feature['value']}, importance: {feature['importance']:.4f})")
            else:
                significant_findings.append(f"{feature['name']}: {feature['value']} (importance: {feature['importance']:.4f})")
    
    report["analysis_result"]["significant_findings"] = significant_findings
    
    return report

def analyze_pdf_file(pdf_path=None, output_json=False, json_output_path=None):
    if pdf_path is None or not os.path.exists(pdf_path):
        root = tk.Tk()
        root.withdraw() 
        pdf_path = filedialog.askopenfilename(
            title="Select PDF File to Analyze",
            filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")]
        )
        if not pdf_path:  
            print("No file selected. Exiting.")
            return None
    
    print(f"Analyzing PDF file: {pdf_path}")
    
    if not os.path.exists(pdf_path):
        print(f"Error: The file '{pdf_path}' does not exist.")
        return None
    
    model_path = "pdf_models/model.pkl"
    scaler_path = "pdf_models/scaler.pkl"
    features_path = "pdf_models/top_features.pkl"
    
    missing_files = []
    for path, name in [(model_path, "Model"), (scaler_path, "Scaler"), (features_path, "Features")]:
        if not os.path.exists(path):
            missing_files.append(f"{name} file '{path}'")
    
    if missing_files:
        print("Error: The following required files are missing:")
        for file in missing_files:
            print(f"  - {file}")
        print("\nPlease update the paths in the script to point to your saved model files.")
        return None
    
    prediction, probability, extracted_features = predict_pdf_malware(pdf_path, model_path, scaler_path, features_path)
    
    if prediction is None or extracted_features is None:
        print("Could not analyze the PDF file")
        return None
    
    report = generate_json_report(pdf_path, prediction, probability, extracted_features)
    
    result = "MALICIOUS" if prediction == 1 else "BENIGN"
    print(f"\nRESULTS:")
    print(f"=========")
    print(f"The PDF file is classified as: {result}")
    print(f"Confidence: {probability:.2%}")
    
    risk_level = report["analysis_result"]["risk_level"]
    print(f"Risk Level: {risk_level}")
    
    print("\nSignificant findings:")
    for finding in report["analysis_result"].get("significant_findings", []):
        print(f"- {finding}")
    
    return report