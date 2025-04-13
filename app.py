import os
import io
import sys
import json
import tempfile
import traceback
from flask import Flask, request, jsonify
from flask import send_file
from flask_cors import CORS
from werkzeug.utils import secure_filename
from model import analyze_file_for_malware
from pe_model import predict_malware_with_analysis
from pdf_model import analyze_pdf_file
from chat import MalwareAnalysisChatbot, JSONReportChatbot
from report import generate_pdf_report
from dy import dy_file

app = Flask(__name__)
CORS(app, origins="*")

app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024
app.config['TEMP_UPLOAD_DIR'] = os.environ.get('TEMP_UPLOAD_DIR', 'temp_uploads')

os.makedirs(app.config['TEMP_UPLOAD_DIR'], exist_ok=True)

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint to verify the service is running."""
    return jsonify({
        'status': 'healthy',
        'message': 'Malware analysis service is operational'
    })

@app.route('/api/analyze', methods=['POST'])
def analyze_file():
    """Endpoint to analyze a single file for potential malware."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'Empty filename provided'}), 400
    
    try:
        # Save the uploaded file to a temporary location
        filename = secure_filename(file.filename)
        temp_dir = tempfile.mkdtemp(dir=app.config['TEMP_UPLOAD_DIR'])
        file_path = os.path.join(temp_dir, filename)
        file.save(file_path)
        
        result = analyze_file_for_malware(file_path)
        
        try:
            os.remove(file_path)
            os.rmdir(temp_dir)
        except Exception as e:
            print(f"Warning: Failed to clean up temporary file: {e}")
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({
            'error': f'Analysis failed: {str(e)}',
            'file_name': file.filename if file else 'Unknown'
        }), 500

@app.route('/api/analyze/batch', methods=['POST'])
def analyze_multiple_files():
    """Endpoint to analyze multiple files in a single request."""
    if 'files' not in request.files:
        return jsonify({'error': 'No files provided'}), 400
    
    files = request.files.getlist('files')
    
    if not files or files[0].filename == '':
        return jsonify({'error': 'No valid files provided'}), 400
    
    results = []
    temp_dir = tempfile.mkdtemp(dir=app.config['TEMP_UPLOAD_DIR'])
    
    try:
        for file in files:
            try:
                filename = secure_filename(file.filename)
                file_path = os.path.join(temp_dir, filename)
                file.save(file_path)
                
                result = analyze_file_for_malware(file_path)
                results.append(result)
                
                try:
                    os.remove(file_path)
                except Exception:
                    pass
                
            except Exception as e:
                results.append({
                    'file_name': file.filename,
                    'is_malicious': 'unknown',
                    'error': f'Analysis failed: {str(e)}'
                })
        
        try:
            os.rmdir(temp_dir)
        except Exception:
            pass
        
        return jsonify({
            'batch_results': results,
            'total_files': len(results)
        })
        
    except Exception as e:
        return jsonify({
            'error': f'Batch analysis failed: {str(e)}',
            'partial_results': results
        }), 500

@app.route('/api/pe', methods=['POST'])
def upload_pe_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    try:
        temp_dir = tempfile.mkdtemp(dir=app.config['TEMP_UPLOAD_DIR'])
        file_path = os.path.join(temp_dir, secure_filename(file.filename))
        file.save(file_path)
        analysis_result = predict_malware_with_analysis(file_path)
        
        try:
            os.remove(file_path)
            os.rmdir(temp_dir)
        except Exception as e:
            print(f"Warning: Failed to clean up temporary file: {e}")

        return jsonify({
            'filename': file.filename,
            'analysis_data': analysis_result
        })
        
    except Exception as e:
        error_message = str(e)
        error_type = type(e).__name__
        
        return jsonify({
            'error': error_message,
            'error_type': error_type,
            'status': 'failure'
        }), 500

@app.route('/api/pe/batch', methods=['POST'])
def upload_pe_batch():
    """Endpoint to analyze multiple PE files in a single request."""
    if 'files' not in request.files:
        return jsonify({'error': 'No files provided'}), 400
    
    files = request.files.getlist('files')
    
    if not files or files[0].filename == '':
        return jsonify({'error': 'No valid files provided'}), 400
    
    results = []
    temp_dir = tempfile.mkdtemp(dir=app.config['TEMP_UPLOAD_DIR'])
    
    try:
        for file in files:
            try:
                filename = secure_filename(file.filename)
                file_path = os.path.join(temp_dir, filename)
                file.save(file_path)
                
                analysis_result = predict_malware_with_analysis(file_path)
                results.append({
                    'filename': file.filename,
                    'analysis_data': analysis_result
                })
                
                try:
                    os.remove(file_path)
                except Exception as e:
                    print(f"Warning: Failed to clean up file {filename}: {e}")
                
            except Exception as e:
                results.append({
                    'filename': file.filename,
                    'status': 'failure',
                    'error': str(e),
                    'error_type': type(e).__name__
                })
        
        try:
            os.rmdir(temp_dir)
        except Exception as e:
            print(f"Warning: Failed to clean up temporary directory: {e}")
        
        return jsonify({
            'batch_results': results,
            'total_files': len(results)
        })
        
    except Exception as e:
        return jsonify({
            'error': f'Batch analysis failed: {str(e)}',
            'error_type': type(e).__name__,
            'partial_results': results,
            'status': 'failure'
        }), 500

@app.route('/api/pdf', methods=['POST'])
def upload_pdf_file():
    """Endpoint to analyze a single PDF file for potential malware."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not file.filename.lower().endswith('.pdf'):
        return jsonify({'error': 'Only PDF files are allowed'}), 400

    temp_dir = None
    file_path = None
    
    try:
        # Create temp directory and save file
        temp_dir = tempfile.mkdtemp(dir=app.config['TEMP_UPLOAD_DIR'])
        filename = secure_filename(file.filename)
        file_path = os.path.join(temp_dir, filename)
        file.save(file_path)

        # Analyze the PDF file
        analysis_report = analyze_pdf_file(file_path, output_json=False)

        # Check if analysis failed
        if analysis_report is None:
            return jsonify({
                'error': 'Analysis failed',
                'status': 'failure'
            }), 500

        # Add the filename to the report
        analysis_report['report_metadata']['filename'] = file.filename
        
        # Return the complete JSON report with a success status
        return jsonify({
            'status': 'success',
            'analysis_report': analysis_report
        })

    except Exception as e:
        error_message = str(e)
        error_type = type(e).__name__

        print(f"Error analyzing PDF: {error_type} - {error_message}")
        import traceback
        traceback.print_exc()

        return jsonify({
            'error': error_message,
            'error_type': error_type,
            'status': 'failure'
        }), 500
        
    finally:
        # Clean up temporary files
        try:
            if file_path and os.path.exists(file_path):
                os.remove(file_path)
            if temp_dir and os.path.exists(temp_dir):
                os.rmdir(temp_dir)
        except Exception as e:
            print(f"Error removing temporary files: {e}")

@app.route('/api/pdf/batch', methods=['POST'])
def upload_pdf_batch():
    """Endpoint to analyze multiple PDF files in a single request."""
    if 'files' not in request.files:
        return jsonify({'error': 'No files provided'}), 400
    
    files = request.files.getlist('files')
    
    if not files or files[0].filename == '':
        return jsonify({'error': 'No valid files provided'}), 400
    
    results = []
    temp_dir = tempfile.mkdtemp(dir=app.config['TEMP_UPLOAD_DIR'])
    
    try:
        for file in files:
            # Check if file is a PDF
            if not file.filename.lower().endswith('.pdf'):
                results.append({
                    'filename': file.filename,
                    'status': 'failure',
                    'error': 'Not a PDF file',
                    'error_type': 'InvalidFileType'
                })
                continue
                
            try:
                filename = secure_filename(file.filename)
                file_path = os.path.join(temp_dir, filename)
                file.save(file_path)
                
                # Analyze the PDF file
                analysis_report = analyze_pdf_file(file_path, output_json=False)
                
                # Check if analysis failed
                if analysis_report is None:
                    results.append({
                        'filename': file.filename,
                        'status': 'failure',
                        'error': 'Analysis failed with unknown error'
                    })
                else:
                    # Add the filename to the report
                    analysis_report['report_metadata']['filename'] = file.filename
                    
                    results.append({
                        'filename': file.filename,
                        'status': 'success',
                        'analysis_report': analysis_report
                    })
                
                # Clean up each file after analysis
                try:
                    os.remove(file_path)
                except Exception as e:
                    print(f"Warning: Failed to clean up file {filename}: {e}")
                
            except Exception as e:
                results.append({
                    'filename': file.filename,
                    'status': 'failure',
                    'error': str(e),
                    'error_type': type(e).__name__
                })
        
        # Clean up temp directory
        try:
            os.rmdir(temp_dir)
        except Exception as e:
            print(f"Warning: Failed to clean up temporary directory: {e}")
        
        return jsonify({
            'batch_results': results,
            'total_files': len(results)
        })
        
    except Exception as e:
        return jsonify({
            'error': f'Batch analysis failed: {str(e)}',
            'error_type': type(e).__name__,
            'partial_results': results,
            'status': 'failure'
        }), 500

@app.route('/api/supported-formats', methods=['GET'])
def supported_formats():
    """Return information about supported file formats for analysis."""
    return jsonify({
        'office_documents': ['.docx', '.xlsx', '.doc', '.xls', '.rtf', '.ppt', '.pptx'],
        'executables': ['.exe', '.dll'],
        'scripts': ['.bat', '.ps1'],
        'pdf': ['.pdf'],
        'other': ['All other file types are supported with basic analysis']
    })

json_chatbot = JSONReportChatbot()
@app.route('/api/chat/analyze', methods=['POST'])
def analyze_via_chat():
    """Endpoint to analyze JSON report data using the chatbot."""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'error': 'No analysis data provided',
                'status': 'failure'
            }), 400
        
        analysis_data = data
        report = json_chatbot.generate_report(analysis_data)
        structured_analysis = json_chatbot.analyze_json_report(analysis_data)
        
        return jsonify({
            'status': 'success',
            'report': report,
            'structured_analysis': structured_analysis
        })
        
    except Exception as e:
        error_message = str(e)
        error_type = type(e).__name__
        
        return jsonify({
            'error': error_message,
            'error_type': error_type,
            'status': 'failure'
        }), 500

@app.route('/api/chat/ask', methods=['POST'])
def ask_chatbot():
    """Endpoint for general malware-related questions."""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'error': 'No question provided',
                'status': 'failure'
            }), 400
        
        question = data['question']
        
        response = json_chatbot.ask(question)
        
        return jsonify({
            'status': 'success',
            'question': question,
            'response': response
        })
        
    except Exception as e:
        error_message = str(e)
        error_type = type(e).__name__
        
        return jsonify({
            'error': error_message,
            'error_type': error_type,
            'status': 'failure'
        }), 500
    
@app.route('/api/generate-report', methods=['POST'])
def generate_report():
    try:
        # Get JSON data from request
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400
            
        # Validate JSON format
        if not isinstance(data, dict):
            return jsonify({"error": "Invalid JSON format, expected a dictionary"}), 400
            
        # Create temporary PDF file
        temp_dir = tempfile.mkdtemp()
        output_path = os.path.join(temp_dir, 'report.pdf')
        
        # Generate report
        print("Generating security report PDF...")
        
        # Ensure the generate_pdf_report function exists
        # If it doesn't, you'll need to implement it
        pdf_path = generate_pdf_report(data, output_path)
        
        # Set proper headers for file download
        response = send_file(
            pdf_path,
            as_attachment=True,
            download_name=f"{data.get('file_name', 'analysis')}-security-report.pdf",
            mimetype='application/pdf'
        )
        
        # Add headers to prevent caching, ensuring fresh download each time
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        response.headers["Content-Disposition"] = f"attachment; filename={data.get('file_name', 'analysis')}-security-report.pdf"
        
        return response
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        print(f"Error generating report: {str(e)}")
        print(traceback.format_exc())
        return jsonify({"error": "Internal server error", "details": str(e)}), 500

@app.route('/api/analyze-dynamic', methods=['POST'])
def analyze_route():
    """
    Process the uploaded file using VirusTotal API and return JSON results
    
    Returns:
        JSON response with analysis results
    """
    # Check if file is present in the request
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in the request'}), 400
    
    file = request.files['file']
    
    # Check if a file was selected
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    try:
        filepath = os.path.join(os.path.join("temp_uploads", file.filename))
        file.save(filepath)
        
        results = dy_file(
            filepath,
            "7393cd0b58277c7af0020bad0fe95d531ba723dfa2035b110f6a1922c21bd090"
        )
        
        try:
            os.remove(filepath)
        except:
            pass  # Ignore errors during cleanup
        
        # Return the JSON results
        return jsonify(results)
    
    except Exception as e:
        # Return error message
        return jsonify({
            'error': 'Analysis failed',
            'message': str(e)
        }), 500   

if __name__ == '__main__':
    if not os.environ.get('GROQ_API_KEY'):
        print("Warning: GROQ_API_KEY environment variable not set!")
    
    app.run(host='0.0.0.0', port=5000, debug=True)