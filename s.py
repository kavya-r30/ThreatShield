import streamlit as st
import os
import sys
import hashlib
import tempfile
import json
from pathlib import Path
from datetime import datetime
import vt
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import time

class VirusTotalScanner:
    def __init__(self, api_key):
        """Initialize the VirusTotal scanner with the provided API key."""
        self.api_key = api_key
        self.client = vt.Client(api_key)
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - ensure we close the API client."""
        self.client.close()
    
    def calculate_file_hash(self, file_path):
        """Calculate SHA256 hash of a file."""
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    
    def scan_file(self, file_path, progress_callback=None):
        """Scan a file using VirusTotal API with progress updates."""
        try:
            file_size = os.path.getsize(file_path)
            if progress_callback:
                progress_callback(0.05, f"File size: {file_size} bytes")
            
            # Calculate file hash
            file_hash = self.calculate_file_hash(file_path)
            if progress_callback:
                progress_callback(0.1, f"File hash (SHA256): {file_hash}")
            
            # First check if the file has already been analyzed
            try:
                if progress_callback:
                    progress_callback(0.15, "Checking if file has already been analyzed...")
                file_report = self.client.get_object(f"/files/{file_hash}")
                if progress_callback:
                    progress_callback(0.9, "File has previously been analyzed by VirusTotal.")
                return self.process_results(file_report)
            except vt.error.APIError as e:
                if e.code == "NotFoundError":
                    if progress_callback:
                        progress_callback(0.2, "File hasn't been analyzed before. Uploading for scanning...")
                else:
                    raise
            
            # Upload the file for scanning
            with open(file_path, "rb") as f:
                if progress_callback:
                    progress_callback(0.25, "Getting upload URL...")
                
                upload_url = self.client.get_json("/files/upload_url")
                
                if progress_callback:
                    progress_callback(0.3, "Uploading file to VirusTotal...")
                
                upload_response = self.client.post(
                    upload_url["url"],
                    files={"file": (os.path.basename(file_path), f)}
                )
                
                analysis_id = upload_response.json().get("data", {}).get("id")
                
                if progress_callback:
                    progress_callback(0.4, f"File uploaded. Analysis ID: {analysis_id}")
                
                if not analysis_id:
                    if progress_callback:
                        progress_callback(1.0, "Error: No analysis ID received from VirusTotal")
                    return None
                
                # Wait for analysis to complete
                if progress_callback:
                    progress_callback(0.45, "Waiting for analysis to complete...")
                
                wait_iterations = 0
                while True:
                    wait_iterations += 1
                    analysis = self.client.get_object(f"/analyses/{analysis_id}")
                    status = analysis.get("status")
                    
                    progress_value = min(0.45 + (wait_iterations * 0.05), 0.85)
                    
                    if status == "completed":
                        if progress_callback:
                            progress_callback(0.9, "Analysis completed.")
                        
                        # Get the full file report
                        file_report = self.client.get_object(f"/files/{file_hash}")
                        return self.process_results(file_report)
                    
                    elif status == "failed":
                        if progress_callback:
                            progress_callback(1.0, "Analysis failed.")
                        return None
                    
                    if progress_callback:
                        progress_callback(progress_value, f"Analysis status: {status}. Waiting...")
                    
                    time.sleep(10)  # Reduced wait time for better UX
        
        except Exception as e:
            if progress_callback:
                progress_callback(1.0, f"Error scanning file: {str(e)}")
            return None
    
    def process_results(self, file_report):
        """Process the results from VirusTotal scan."""
        try:
            # Extract the most important detection information
            last_analysis_results = file_report.get("last_analysis_results", {})
            stats = file_report.get("last_analysis_stats", {})
            
            total_engines = sum(stats.values())
            malicious_count = stats.get("malicious", 0)
            suspicious_count = stats.get("suspicious", 0)
            
            # Create result object
            result = {
                "file_info": {
                    "name": file_report.get("meaningful_name", "Unknown"),
                    "size": file_report.get("size", 0),
                    "type": file_report.get("type_description", "Unknown"),
                    "sha256": file_report.get("sha256", ""),
                    "md5": file_report.get("md5", ""),
                    "first_seen": file_report.get("first_submission_date", 0),
                    "last_seen": file_report.get("last_analysis_date", 0),
                },
                "scan_results": {
                    "total_engines": total_engines,
                    "malicious": malicious_count,
                    "suspicious": suspicious_count,
                    "detection_rate": f"{(malicious_count + suspicious_count) / total_engines * 100:.2f}%" if total_engines > 0 else "N/A",
                    "detections": []
                },
                "detailed_results": {}
            }
            
            # Add detailed detection information
            for engine_name, engine_result in last_analysis_results.items():
                result["detailed_results"][engine_name] = {
                    "category": engine_result.get("category", ""),
                    "result": engine_result.get("result", ""),
                    "engine_name": engine_result.get("engine_name", engine_name),
                    "engine_version": engine_result.get("engine_version", ""),
                }
                
                if engine_result.get("category") in ["malicious", "suspicious"]:
                    result["scan_results"]["detections"].append({
                        "engine": engine_name,
                        "category": engine_result.get("category", ""),
                        "result": engine_result.get("result", "")
                    })
            
            return result
            
        except Exception as e:
            st.error(f"Error processing results: {str(e)}")
            return None


def save_uploaded_file(uploaded_file):
    """Save an uploaded file to a temporary location and return the path."""
    try:
        # Create a temporary file
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=f"_{uploaded_file.name}")
        temp_file.write(uploaded_file.getvalue())
        temp_file.close()
        return temp_file.name
    except Exception as e:
        st.error(f"Error saving uploaded file: {str(e)}")
        return None


def display_file_info(result):
    """Display basic file information."""
    file_info = result["file_info"]
    
    st.subheader("File Information")
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown(f"**Name:** {file_info['name']}")
        st.markdown(f"**Size:** {file_info['size']:,} bytes")
        st.markdown(f"**Type:** {file_info['type']}")
    
    with col2:
        first_seen = datetime.fromtimestamp(file_info['first_seen']).strftime('%Y-%m-%d %H:%M:%S') if file_info['first_seen'] else "N/A"
        last_seen = datetime.fromtimestamp(file_info['last_seen']).strftime('%Y-%m-%d %H:%M:%S') if file_info['last_seen'] else "N/A"
        
        st.markdown(f"**First Seen:** {first_seen}")
        st.markdown(f"**Last Analyzed:** {last_seen}")
    
    with st.expander("Hash Information"):
        st.markdown(f"**SHA256:** `{file_info['sha256']}`")
        st.markdown(f"**MD5:** `{file_info['md5']}`")


def display_scan_summary(result):
    """Display a summary of the scan results with visual indicators."""
    scan_results = result["scan_results"]
    total_engines = scan_results['total_engines']
    malicious = scan_results['malicious']
    suspicious = scan_results['suspicious']
    clean = total_engines - malicious - suspicious
    
    st.subheader("Scan Summary")
    
    # Create a detection rate progress bar
    detection_rate_raw = float(scan_results['detection_rate'].strip('%')) if scan_results['detection_rate'] != "N/A" else 0
    
    col1, col2 = st.columns([1, 2])
    
    with col1:
        if detection_rate_raw > 20:
            st.error(f"### Detection Rate: {scan_results['detection_rate']}")
            st.error("### High Risk")
        elif detection_rate_raw > 5:
            st.warning(f"### Detection Rate: {scan_results['detection_rate']}")
            st.warning("### Medium Risk")
        elif detection_rate_raw > 0:
            st.info(f"### Detection Rate: {scan_results['detection_rate']}")
            st.info("### Low Risk")
        else:
            st.success(f"### Detection Rate: {scan_results['detection_rate']}")
            st.success("### Clean")
    
    with col2:
        # Create data for the donut chart
        labels = ['Clean', 'Malicious', 'Suspicious']
        values = [clean, malicious, suspicious]
        colors = ['green', 'red', 'orange']
        
        fig = go.Figure(data=[go.Pie(
            labels=labels,
            values=values,
            hole=.4,
            marker=dict(colors=colors)
        )])
        
        fig.update_layout(
            title="Antivirus Engine Results",
            height=300,
            margin=dict(l=20, r=20, t=40, b=20),
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    # Display recommendation
    if detection_rate_raw > 20:
        st.error("⚠️ **HIGH RISK**: This file is likely malicious. Do not execute or open it.")
    elif detection_rate_raw > 5:
        st.warning("⚠️ **MEDIUM RISK**: This file is suspicious. Handle with caution.")
    elif detection_rate_raw > 0:
        st.info("⚠️ **LOW RISK**: This file has minimal detections but still requires caution.")
    else:
        st.success("✅ **No threats detected** by any engine. File appears to be safe.")


def display_detections(result):
    """Display detailed detection information."""
    scan_results = result["scan_results"]
    detections = scan_results.get("detections", [])
    
    if detections:
        st.subheader("Malware Detections")
        
        # Create dataframe for detections
        df_detections = pd.DataFrame(detections)
        
        # Sort by category (malicious first, then suspicious)
        df_detections = df_detections.sort_values(by="category")
        
        # Add styled rows
        st.dataframe(
            df_detections,
            column_config={
                "engine": "Antivirus Engine",
                "category": "Threat Category",
                "result": "Detection Name"
            },
            height=min(35 * (len(detections) + 1), 400)
        )
    else:
        st.success("No threats were detected by any antivirus engine.")


def display_all_results(result):
    """Display complete scan results from all engines."""
    detailed_results = result.get("detailed_results", {})
    
    if detailed_results:
        st.subheader("Complete Scan Results")
        
        # Create dataframe for all results
        data = []
        for engine_name, details in detailed_results.items():
            data.append({
                "engine": engine_name,
                "category": details.get("category", ""),
                "result": details.get("result", ""),
                "engine_version": details.get("engine_version", "")
            })
        
        df_all_results = pd.DataFrame(data)
        
        # Add category filter
        categories = ["All"] + sorted(df_all_results["category"].unique().tolist())
        selected_category = st.selectbox("Filter by Category:", categories)
        
        if selected_category != "All":
            filtered_df = df_all_results[df_all_results["category"] == selected_category]
        else:
            filtered_df = df_all_results
        
        # Sort results
        filtered_df = filtered_df.sort_values(by=["category", "engine"])
        
        # Display results table
        st.dataframe(
            filtered_df,
            column_config={
                "engine": "Antivirus Engine",
                "category": "Category",
                "result": "Result",
                "engine_version": "Engine Version"
            },
            height=min(35 * (len(filtered_df) + 1), 400)
        )
        
        # Show category distribution
        category_counts = df_all_results["category"].value_counts().reset_index()
        category_counts.columns = ["category", "count"]
        
        fig = px.bar(
            category_counts, 
            x="category", 
            y="count",
            color="category",
            labels={"category": "Category", "count": "Number of Engines"},
            title="Results by Category"
        )
        
        fig.update_layout(
            xaxis_title="Category",
            yaxis_title="Number of Engines",
            height=400
        )
        
        st.plotly_chart(fig, use_container_width=True)


def main():
    st.set_page_config(
        page_title="VirusTotal Sandbox Scanner",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    st.title("🛡️ VirusTotal Sandbox Scanner")
    st.markdown("""
    Upload files to scan them for malware using VirusTotal's multi-engine detection system.
    This tool provides sandboxed analysis of files without executing them on your local system.
    """)
    
    # Initialize session state
    if "scan_history" not in st.session_state:
        st.session_state.scan_history = []
    
    if "scanning" not in st.session_state:
        st.session_state.scanning = False
    
    if "scan_completed" not in st.session_state:
        st.session_state.scan_completed = False
        
    if "current_result" not in st.session_state:
        st.session_state.current_result = None
        
    # Sidebar for configuration
    st.sidebar.header("Configuration")
    
    # API Key input
    default_api_key = "8854e345f697a63911f5e0c6e1cdd27d67af5f19dea79621947d255ae8074866"
    api_key = st.sidebar.text_input(
        "VirusTotal API Key", 
        value=default_api_key,
        type="password",
        help="Enter your VirusTotal API key. Default key is provided but may have rate limits."
    )
    
    # File uploader
    st.sidebar.header("Upload File")
    uploaded_file = st.sidebar.file_uploader(
        "Select a file to scan",
        help="Files will be sent to VirusTotal for analysis.",
        on_change=lambda: setattr(st.session_state, "scan_completed", False)
    )
    
    # Scan button
    scan_button = st.sidebar.button("Scan File", disabled=not uploaded_file or st.session_state.scanning)
    
    # History
    st.sidebar.header("Scan History")
    
    if st.session_state.scan_history:
        for i, item in enumerate(st.session_state.scan_history):
            if st.sidebar.button(f"{item['name']} ({item['result']})", key=f"history_{i}"):
                st.session_state.current_result = item["full_result"]
                st.session_state.scan_completed = True
    else:
        st.sidebar.info("No scan history yet")
    
    # Clear history button
    if st.session_state.scan_history and st.sidebar.button("Clear History"):
        st.session_state.scan_history = []
        st.session_state.current_result = None
        st.session_state.scan_completed = False
    
    # About section
    st.sidebar.header("About")
    st.sidebar.info("""
    This tool uses the VirusTotal API to scan files with 70+ antivirus engines.
    No files are executed on your system, making this a safe way to analyze
    potentially dangerous files.
    """)
    
    # Main content area
    if scan_button and uploaded_file and not st.session_state.scanning:
        st.session_state.scanning = True
        
        # Save uploaded file and scan it
        temp_file_path = save_uploaded_file(uploaded_file)
        
        if temp_file_path:
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            def update_progress(progress, message):
                progress_bar.progress(progress)
                status_text.text(message)
            
            try:
                with VirusTotalScanner(api_key) as scanner:
                    result = scanner.scan_file(temp_file_path, update_progress)
                    
                    if result:
                        # Add to scan history
                        detection_rate = result["scan_results"]["detection_rate"]
                        rate_value = float(detection_rate.strip('%')) if detection_rate != "N/A" else 0
                        
                        if rate_value > 20:
                            risk_level = "High Risk"
                        elif rate_value > 5:
                            risk_level = "Medium Risk"
                        elif rate_value > 0:
                            risk_level = "Low Risk"
                        else:
                            risk_level = "Clean"
                        
                        # Add to history
                        history_item = {
                            "name": result["file_info"]["name"],
                            "result": risk_level,
                            "full_result": result
                        }
                        
                        # Insert at the beginning
                        st.session_state.scan_history.insert(0, history_item)
                        
                        # Limit history size
                        if len(st.session_state.scan_history) > 10:
                            st.session_state.scan_history = st.session_state.scan_history[:10]
                        
                        # Set as current result
                        st.session_state.current_result = result
                        st.session_state.scan_completed = True
                    
                    # Clean up temp file
                    if os.path.exists(temp_file_path):
                        os.unlink(temp_file_path)
                    
                    # Complete progress
                    progress_bar.progress(1.0)
                    status_text.text("Scan complete!")
                    time.sleep(1)
                    
            except Exception as e:
                st.error(f"Error during scanning: {str(e)}")
                if os.path.exists(temp_file_path):
                    os.unlink(temp_file_path)
            
            finally:
                st.session_state.scanning = False
                # Clear progress indicators
                status_text.empty()
                progress_bar.empty()
    
    # Display ongoing scan status
    if st.session_state.scanning:
        st.info("Scanning file... Please wait.")
    
    # Display results if available
    elif st.session_state.scan_completed and st.session_state.current_result:
        result = st.session_state.current_result
        
        # Display file information and results
        display_file_info(result)
        st.markdown("---")
        display_scan_summary(result)
        st.markdown("---")
        display_detections(result)
        
        # Download options
        col1, col2 = st.columns(2)
        with col1:
            st.download_button(
                "Download Full Report (JSON)",
                data=json.dumps(result, indent=4),
                file_name=f"vt_report_{result['file_info']['name']}.json",
                mime="application/json"
            )
        
        # Show detailed results in an expander
        with st.expander("Show Complete Scan Results"):
            display_all_results(result)
    
    elif uploaded_file and not st.session_state.scan_completed:
        st.info("Click 'Scan File' to begin analysis.")


if __name__ == "__main__":
    main()