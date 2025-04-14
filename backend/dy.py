import os
import time
import json
import hashlib
import requests
from dotenv import load_dotenv
from datetime import datetime

def dy_file(file_path, api_key=None, return_report=True):
    load_dotenv()
    
    if api_key is None:
        api_key = os.environ.get('DYNAMIC_API_KEY')
        if api_key is None:
            raise ValueError("DYNAMIC_API_KEY API key not provided.")
    
    base_url = "https://www.virustotal.com/api/v3"
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json"
    }
    results = {
        "file_info": {
            "name": os.path.basename(file_path),
            "size": os.path.getsize(file_path),
            "path": os.path.abspath(file_path),
            "analysis_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    }
    
    print("Calculating file hashes...")
    hashes = _calculate_file_hash(file_path)
    results["file_info"]["hashes"] = hashes
    
    print(f"Checking if file already exists in VirusTotal database...")
    existing_report = _get_file_report(base_url, headers, hashes["sha256"])
    
    if existing_report:
        print("File found in VirusTotal database. Retrieving report...")
        results["static_analysis"] = existing_report
    else:
        print("File not found in VirusTotal database. Uploading for analysis...")
        upload_response = _upload_file(file_path, base_url, headers)
        analysis_id = upload_response["data"]["id"]
        print(f"File uploaded successfully. Analysis ID: {analysis_id}")
        
        print("Waiting for analysis to complete...")
        analysis_report = _get_analysis_report(analysis_id, base_url, headers)
        results["static_analysis"] = analysis_report
    
    print("Retrieving behavioral analysis data...")
    behavior_data = _get_file_behavior(hashes["sha256"], base_url, headers)
    results["dynamic_analysis"] = behavior_data
    
    if return_report:
        report = _generate_report(results)
        results["report"] = report
    
    return results

def _calculate_file_hash(file_path):
    hashes = {}
    
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"The file {file_path} does not exist")
    
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()
    
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            md5_hash.update(chunk)
            sha1_hash.update(chunk)
            sha256_hash.update(chunk)
    
    hashes["md5"] = md5_hash.hexdigest()
    hashes["sha1"] = sha1_hash.hexdigest()
    hashes["sha256"] = sha256_hash.hexdigest()
    
    return hashes

def _upload_file(file_path, base_url, headers):
    """Upload a file to VirusTotal for analysis."""
    upload_url = f"{base_url}/files"
    
    with open(file_path, "rb") as file:
        files = {"file": (os.path.basename(file_path), file)}
        response = requests.post(upload_url, headers=headers, files=files)
    
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"File upload failed with status code {response.status_code}: {response.text}")

def _get_analysis_report(file_id, base_url, headers, max_attempts=10, wait_time=30):
    analysis_url = f"{base_url}/analyses/{file_id}"
    
    for attempt in range(max_attempts):
        response = requests.get(analysis_url, headers=headers)
        
        if response.status_code == 200:
            report = response.json()
            if report["data"]["attributes"]["status"] == "completed":
                return report
            else:
                print(f"Analysis in progress... waiting {wait_time} seconds (attempt {attempt + 1}/{max_attempts})")
                time.sleep(wait_time)
        else:
            raise Exception(f"Failed to get analysis report with status code {response.status_code}: {response.text}")
    
    raise TimeoutError(f"Analysis did not complete after {max_attempts} attempts")

def _get_file_report(base_url, headers, file_hash):
    report_url = f"{base_url}/files/{file_hash}"
    
    response = requests.get(report_url, headers=headers)
    
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 404:
        return None 
    else:
        raise Exception(f"Failed to get file report with status code {response.status_code}: {response.text}")

def _get_file_behavior(file_hash, base_url, headers):
    behavior_url = f"{base_url}/files/{file_hash}/behaviours"
    
    response = requests.get(behavior_url, headers=headers)
    
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 404:
        return None
    else:
        raise Exception(f"Failed to get behavior report with status code {response.status_code}: {response.text}")

def _generate_report(analysis_results):
    report = []
    
    file_info = analysis_results["file_info"]
    report.append("=" * 80)
    report.append("MALWARE ANALYSIS REPORT")
    report.append("=" * 80)
    report.append(f"File Name: {file_info['name']}")
    report.append(f"File Size: {file_info['size']} bytes")
    report.append(f"File Path: {file_info['path']}")
    report.append(f"Analysis Time: {file_info['analysis_time']}")
    report.append("")
    report.append("File Hashes:")
    report.append(f"  MD5:    {file_info['hashes']['md5']}")
    report.append(f"  SHA-1:  {file_info['hashes']['sha1']}")
    report.append(f"  SHA-256: {file_info['hashes']['sha256']}")
    report.append("")
    
    if analysis_results.get("static_analysis"):
        static_data = analysis_results["static_analysis"]["data"]
        if "attributes" in static_data:
            attrs = static_data["attributes"]
            
            if "stats" in attrs:
                stats = attrs["stats"]
                report.append("-" * 80)
                report.append("DETECTION STATISTICS")
                report.append("-" * 80)
                total = stats.get("total", 0)
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                undetected = stats.get("undetected", 0)
                
                if total > 0:
                    detection_rate = (malicious + suspicious) / total * 100
                else:
                    detection_rate = 0
                
                report.append(f"Detection Rate: {detection_rate:.2f}% ({malicious + suspicious}/{total})")
                report.append(f"  Malicious:  {malicious}")
                report.append(f"  Suspicious:  {suspicious}")
                report.append(f"  Undetected:  {undetected}")
                report.append("")
    
    if analysis_results.get("dynamic_analysis") and analysis_results["dynamic_analysis"] is not None:
        dynamic_data = analysis_results["dynamic_analysis"]["data"]
        if dynamic_data:
            report.append("-" * 80)
            report.append("DYNAMIC ANALYSIS RESULTS")
            report.append("-" * 80)
            
            for i, sandbox in enumerate(dynamic_data[:3]):
                attrs = sandbox.get("attributes", {})
                
                sandbox_id = attrs.get("sandbox_name", f"Sandbox {i+1}")
                report.append(f"Sandbox: {sandbox_id}")
                
                processes = attrs.get("processes", [])
                if processes:
                    report.append("\nProcesses Created:")
                    for proc in processes[:10]:
                        report.append(f"  * {proc.get('name', 'Unknown')} (PID: {proc.get('pid', 'N/A')})")
                
                network = attrs.get("network", {})
                dns_requests = network.get("dns", [])
                if dns_requests:
                    report.append("\nDNS Requests:")
                    for dns in dns_requests[:10]: 
                        report.append(f"  * {dns.get('hostname', 'Unknown')}")
                
                http_requests = network.get("http", [])
                if http_requests:
                    report.append("\nHTTP Requests:")
                    for http in http_requests[:10]:
                        report.append(f"  * {http.get('url', 'Unknown')}")
                
                registry = attrs.get("registry", {})
                keys_set = registry.get("keys_set", [])
                if keys_set:
                    report.append("\nRegistry Keys Modified:")
                    for key in keys_set[:10]:
                        report.append(f"  * {key}")
                
                files = attrs.get("files", {})
                files_written = files.get("written", [])
                if files_written:
                    report.append("\nFiles Written:")
                    for file in files_written[:10]:  
                        report.append(f"  * {file}")
                
                report.append("\n" + "-" * 40)
            
            if dynamic_data and len(dynamic_data) > 0:
                report.append("\nBehavioral Summary:")
                
                behaviors = []
                for sandbox in dynamic_data:
                    attrs = sandbox.get("attributes", {})
                    
                    processes = attrs.get("processes", [])
                    for proc in processes:
                        if "injection" in proc.get("name", "").lower():
                            behaviors.append("Process injection detected")
                            break
                    
                    registry = attrs.get("registry", {})
                    keys_set = registry.get("keys_set", [])
                    for key in keys_set:
                        if "run" in key.lower() or "startup" in key.lower():
                            behaviors.append("Persistence mechanism detected (autorun registry keys)")
                            break
                    
                    network = attrs.get("network", {})
                    http_requests = network.get("http", [])
                    if http_requests:
                        behaviors.append("Network communication detected")
                
                behaviors = list(set(behaviors))
                
                if behaviors:
                    for behavior in behaviors:
                        report.append(f"  * {behavior}")
                else:
                    report.append("  * No significant suspicious behaviors detected")
    else:
        report.append("-" * 80)
        report.append("DYNAMIC ANALYSIS RESULTS")
        report.append("-" * 80)
        report.append("No dynamic analysis data available for this file")
    
    report.append("\n" + "=" * 80)
    report.append("CONCLUSION")
    report.append("=" * 80)
    
    static_data = analysis_results.get("static_analysis", {}).get("data", {})
    attrs = static_data.get("attributes", {})
    stats = attrs.get("stats", {})
    
    total = stats.get("total", 0)
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    
    if total > 0:
        detection_rate = (malicious + suspicious) / total * 100
        
        if detection_rate >= 50:
            verdict = "HIGH RISK - This file is likely malicious"
        elif detection_rate >= 10:
            verdict = "MEDIUM RISK - This file is suspicious and requires further investigation"
        else:
            verdict = "LOW RISK - This file appears to be clean, but exercise caution"
    else:
        verdict = "UNKNOWN RISK - Insufficient data to determine risk level"
    
    report.append(verdict)
    
    return "\n".join(report)

