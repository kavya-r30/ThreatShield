import os
import json
import tempfile
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Image, Table, TableStyle, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from langchain.schema import HumanMessage, SystemMessage
from langchain_groq import ChatGroq
from dotenv import load_dotenv
import numpy as np

def generate_report_with_groq(data, api_key):
    api_key = api_key or os.getenv("GROQ_API_KEY")
    if not api_key:
        raise ValueError("Groq API key not provided. Set it in a .env file.")
    
    chat = ChatGroq(
        api_key=api_key,
        model_name="llama-3.3-70b-versatile"
    )
    
    system_prompt = """
    You are a senior cybersecurity analyst with expertise in malware and script and files analysis. Analyze the provided JSON data, which contains details about a potentially malicious script (e.g., script name, confidence levels, detected threats, behaviors). Generate a detailed, professional report for a dashboard-style presentation, including:

    1. **Executive Summary** (100-150 words):
       - Provide a comprehensive overview of the script's behavior.
       - If the file is LEGITIMATE or BENIGN (e.g., malice_confidence < 30, no significant threats like infinite_loops), state it clearly and discuss minor risks (e.g., unverified sources, unusual system calls, potential misuse).
       - If malicious (e.g., malice_confidence >= 70 or detected threats), highlight primary risks (e.g., system disruption, data theft) and severity.
       - Mention the confidence level and critical impacts (e.g., denial of service).

    2. **Key Findings** (4-6 insights):
       - Identify significant behaviors (e.g., infinite loops, file manipulation) for malicious files, or benign behaviors with minor risks for LEGITIMATE/BENIGN files.
       - Include specific metrics (e.g., confidence percentage, number of instances) for all numeric fields.
       - Provide context explaining the impact on system security or performance.
       - Avoid using risk scores or severity metrics.

    3. **Detailed Analysis** (3-4 sections, 50-100 words each):
       - Break down the script’s behavior into categories (e.g., Code Structure, Execution Flow, System Interaction, Network Activity).
       - Analyze technical details (e.g., loop mechanisms, system calls).
       - For BENIGN files, highlight patterns that suggest caution (e.g., unverified dependencies).
       - For malicious files, note anomalies indicating intent and assess damage (e.g., CPU overload, data exfiltration).

    4. **Recommendations** (4-6 actionable steps):
       - For malicious files, suggest precise mitigations (e.g., isolate script, patch vulnerabilities).
       - For BENIGN files, recommend cautionary measures (e.g., verify source, run in sandbox).
       - Assign priorities (High, Medium, Low) based on likelihood and impact.
       - Tailor advice to a technical audience, assuming enterprise-level systems.

    For visualizations, recommend 3-4 specific, dashboard-friendly charts to highlight all numeric metrics in the JSON data:
    - Examples: Bar chart for malice_confidence, system_calls, file_modifications; pie chart for categorical distributions (e.g., loop_type); horizontal bar for single metrics.
    - Use actual JSON fields (e.g., malice_confidence, infinite_loops, system_calls, file_modifications, network_requests) and avoid risk scores or severity metrics.
    - Ensure charts are clear, with relevant data fields and descriptions matching the report’s metrics.

    Respond with a JSON object:
    {
        "report": {
            "title": "Script Analysis Report",
            "executive_summary": "Detailed summary text",
            "key_findings": [{"title": "Finding", "metric": "Value", "context": "Explanation"}, ...],
            "detailed_analysis": [{"section": "Title", "content": "Analysis"}, ...],
            "recommendations": [{"priority": "High/Medium/Low", "action": "Action"}, ...],
            "final_verdict": "The file is LEGITIMATE/BENIGN with minor risks: [reason] | malicious due to [reason]."
        },
        "visualizations": [
            {
                "title": "Chart title",
                "type": "bar|pie|horizontal_bar",
                "description": "What this chart shows",
                "data_fields": ["field1", "field2"],
                "metrics": {"x": "field", "y": "field", "group_by": "field"}
            },
            ...
        ]
    }
    """
    
    messages = [
        SystemMessage(content=system_prompt),
        HumanMessage(content=f"JSON data: {json.dumps(data, indent=2)}")
    ]
    
    try:
        response = chat.invoke(messages)
        response_content = response.content
        if "```json" in response_content:
            response_content = response_content.split("```json")[1].split("```")[0].strip()
        return json.loads(response_content)
    except Exception as e:
        raise Exception(f"Error parsing Groq response: {str(e)}")

def create_visualizations(data, groq_report):
    visualization_files = []
    temp_dir = tempfile.mkdtemp()
    
    # Convert data to DataFrame
    try:
        if isinstance(data, list):
            df = pd.DataFrame(data)
        elif isinstance(data, dict):
            if any(isinstance(v, (dict, list)) for v in data.values()):
                df = pd.json_normalize(data)
            else:
                df = pd.DataFrame([data])
        else:
            raise ValueError("Unsupported data format")
        
        if df.empty:
            raise ValueError("Empty DataFrame after processing")
    except Exception as e:
        raise Exception(f"Error processing data for visualization: {str(e)}")
    
    # Set dashboard-style plotting
    try:
        plt.style.use('seaborn-v0_8')
    except:
        plt.style.use('ggplot')
    sns.set_palette("crest")
    sns.set_context("notebook", font_scale=0.9)
    
    # Extract numeric fields from JSON and key_findings
    numeric_cols = [col for col in df.select_dtypes(include=['number']).columns if col.lower() not in ['resource_risk', 'risk_score', 'severity_score', 'severity']]
    finding_metrics = [f.get('metric', '') for f in groq_report.get('report', {}).get('key_findings', [])]
    print(f"Numeric columns: {numeric_cols}")
    print(f"Report metrics: {finding_metrics}")
    
    for i, viz in enumerate(groq_report.get('visualizations', [])):
        try:
            fig = plt.figure(figsize=(5.5, 3.5), dpi=250)
            title = viz.get('title', f'Chart {i+1}')
            viz_type = viz.get('type', 'bar').lower()
            data_fields = viz.get('data_fields', [])
            
            # Validate data fields
            risk_fields = ['resource_risk', 'risk_score', 'severity_score', 'severity']
            available_fields = [f for f in data_fields if f in df.columns and f.lower() not in risk_fields]
            if not available_fields or len(available_fields) < 2:
                if numeric_cols:
                    if len(numeric_cols) > 1:
                        available_fields = ['script_name', numeric_cols[0]] if 'script_name' in df.columns else [numeric_cols[0], numeric_cols[1]]
                    else:
                        available_fields = ['index', numeric_cols[0]]
                        df = df.reset_index()
                else:
                    print(f"Warning: No numeric data for {title}, skipping")
                    plt.close()
                    continue
            
            # Ensure chart matches report
            metric_value = None
            for finding in finding_metrics:
                if any(field in finding.lower() for field in available_fields):
                    metric_value = finding
                    break
            
            print(f"Chart {title}: Using fields {available_fields}, matches metric: {metric_value}")
            
            # Create visualization
            if viz_type == 'bar':
                sns.barplot(data=df, x=available_fields[0], y=available_fields[1], color='#1e4d7a')
                for patch in plt.gca().patches:
                    plt.gca().text(patch.get_x() + patch.get_width()/2, patch.get_height() + 0.5,
                                 f'{int(patch.get_height())}', ha='center', fontsize=7)
                plt.xticks(rotation=20, fontsize=7)
                plt.gca().set_facecolor('#f8fafc')
                plt.grid(True, axis='y', linestyle='--', alpha=0.3)
            
            elif viz_type == 'pie':
                value_counts = df[available_fields[0]].value_counts()
                wedges, texts, autotexts = plt.pie(value_counts, labels=value_counts.index,
                                                  autopct='%1.0f%%', startangle=90,
                                                  colors=sns.color_palette("crest"),
                                                  textprops={'fontsize': 7})
                for autotext in autotexts:
                    autotext.set_color('white')
                    autotext.set_fontweight('bold')
                plt.axis('equal')
                plt.gca().set_facecolor('#f8fafc')
            
            elif viz_type == 'horizontal_bar':
                value = df[available_fields[1]].iloc[0] if len(df) > 0 and len(available_fields) > 1 else 20
                plt.barh([available_fields[1]], [value], color='#1e4d7a', height=0.4, alpha=0.9)
                plt.xlim(0, max(value + 10, 100))
                plt.text(value - 5, 0, f'{int(value)}', va='center', color='white', fontsize=8, fontweight='bold')
                plt.gca().set_yticks([available_fields[1]])
                plt.gca().set_xticks([0, value, max(value + 10, 100)])
                plt.gca().tick_params(axis='x', labelsize=7)
                plt.gca().set_facecolor('#f8fafc')
                plt.grid(True, axis='x', linestyle='--', alpha=0.3)
            
            plt.title(title, fontsize=10, pad=8, color='#1a3c5e', fontweight='bold')
            plt.tight_layout(pad=0.7)
            
            file_path = os.path.join(temp_dir, f'chart_{i+1}.png')
            plt.savefig(file_path, bbox_inches='tight', dpi=250, facecolor='#f8fafc')
            plt.close()
            
            visualization_files.append({
                'path': file_path,
                'title': title,
                'description': viz.get('description', '')
            })
            
        except Exception as e:
            print(f"Error creating visualization {title}: {str(e)}")
            plt.close()
    
    # Add a summary bar chart for all numeric fields
    if len(numeric_cols) > 1:
        try:
            fig = plt.figure(figsize=(5.5, 3.5), dpi=250)
            summary_data = {col: df[col].iloc[0] for col in numeric_cols}
            summary_df = pd.DataFrame({'Metric': summary_data.keys(), 'Value': summary_data.values()})
            sns.barplot(data=summary_df, x='Metric', y='Value', color='#1e4d7a')
            for patch in plt.gca().patches:
                plt.gca().text(patch.get_x() + patch.get_width()/2, patch.get_height() + 0.5,
                             f'{int(patch.get_height())}', ha='center', fontsize=7)
            plt.xticks(rotation=20, fontsize=7)
            plt.title("Summary of Numeric Metrics", fontsize=10, pad=8, color='#1a3c5e', fontweight='bold')
            plt.gca().set_facecolor('#f8fafc')
            plt.grid(True, axis='y', linestyle='--', alpha=0.3)
            plt.tight_layout(pad=0.7)
            
            file_path = os.path.join(temp_dir, 'summary_chart.png')
            plt.savefig(file_path, bbox_inches='tight', dpi=250, facecolor='#f8fafc')
            plt.close()
            
            visualization_files.append({
                'path': file_path,
                'title': "Summary of Numeric Metrics",
                'description': "Comparison of all numeric metrics from the script analysis."
            })
        except Exception as e:
            print(f"Error creating summary chart: {str(e)}")
            plt.close()
    
    return visualization_files

def create_pdf_report(groq_report, visualization_files, output_path):
    doc = SimpleDocTemplate(output_path, pagesize=letter, leftMargin=0.25*inch, rightMargin=0.25*inch,
                          topMargin=0.25*inch, bottomMargin=0.25*inch)
    styles = getSampleStyleSheet()
    
    # Fancy dashboard styles
    title_style = ParagraphStyle(
        'DashboardTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=18,
        spaceAfter=14,
        spaceBefore=8,
        textColor=colors.white,
        backColor=colors.HexColor('#1a3c5e'),
        borderPadding=(8, 10),
        alignment=1,
        borderWidth=1.5,
        borderColor=colors.HexColor('#b0c4de')
    )
    
    section_style = ParagraphStyle(
        'SectionTitle',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=12,
        spaceAfter=2,
        spaceBefore=4,
        textColor=colors.HexColor('#2b6ca3'),
        leftIndent=2
    )
    
    metric_style = ParagraphStyle(
        'Metric',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        spaceAfter=1,
        spaceBefore=1,
        textColor=colors.HexColor('#333333'),
        leading=10
    )
    
    body_style = ParagraphStyle(
        'DashboardBody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=9.5,
        spaceAfter=1.5,
        textColor=colors.HexColor('#333333')
    )
    
    verdict_style = ParagraphStyle(
        'Verdict',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10,
        spaceAfter=6,
        spaceBefore=6,
        leading=12,
        alignment=1
    )
    
    # Build dashboard layout
    elements = []
    
    # Header
    report_title = groq_report.get('report', {}).get('title', 'File Analysis Report')
    elements.append(Paragraph(report_title, title_style))
    elements.append(Spacer(1, 0.1*inch))
    
    # Final Verdict with dynamic color
    final_verdict = groq_report.get('report', {}).get('final_verdict', 'No verdict provided.')
    verdict_color = colors.HexColor('#388e3c') if 'LEGITIMATE' in final_verdict.upper() or 'BENIGN' in final_verdict.upper() else colors.HexColor('#d32f2f')
    verdict_style.textColor = verdict_color
    elements.append(Paragraph(final_verdict, verdict_style))
    elements.append(Spacer(1, 0.1*inch))
    
    # Two-column layout
    left_content = []
    right_content = []
    
    # Left column: Summary, Findings
    left_content.append(Paragraph("Executive Summary", section_style))
    summary = groq_report.get('report', {}).get('executive_summary', '')
    left_content.append(Paragraph(summary, body_style))
    
    left_content.append(Paragraph("Key Findings", section_style))
    findings = groq_report.get('report', {}).get('key_findings', [])
    for finding in findings[:3]:
        text = f"<b>{finding.get('title', 'Finding')}:</b> {finding.get('metric', '')}<br/>{finding.get('context', '')}"
        left_content.append(Paragraph(text, metric_style))
    
    # Right column: Visualizations, Recommendations, Analysis
    if visualization_files:
        right_content.append(Paragraph("Key Metrics", section_style))
        for viz in visualization_files[:3]:
            right_content.append(Paragraph(viz['title'], metric_style))
            img = Image(viz['path'], width=2.8*inch, height=1.8*inch)
            img.hAlign = 'CENTER'
            right_content.append(img)
    
    right_content.append(Paragraph("Recommendations", section_style))
    recommendations = groq_report.get('report', {}).get('recommendations', [])
    for rec in recommendations[:3]:
        text = f"<b>{rec.get('priority', 'Priority')}:</b> {rec.get('action', '')}"
        right_content.append(Paragraph(text, metric_style))
    
    # Move Detailed Analysis to right column if space allows, else to left
    analysis = groq_report.get('report', {}).get('detailed_analysis', [])
    if len(right_content) < len(left_content) + 2:
        right_content.append(Paragraph("Detailed Analysis", section_style))
        for section in analysis[:2]:
            right_content.append(Paragraph(section.get('section', 'Analysis'), metric_style))
            right_content.append(Paragraph(section.get('content', ''), body_style))
    else:
        left_content.append(Paragraph("Detailed Analysis", section_style))
        for section in analysis[:2]:
            left_content.append(Paragraph(section.get('section', 'Analysis'), metric_style))
            left_content.append(Paragraph(section.get('content', ''), body_style))
    
    # Balance columns
    max_len = max(len(left_content), len(right_content))
    content_data = []
    for i in range(max_len):
        left_item = left_content[i] if i < len(left_content) else Paragraph("", body_style)
        right_item = right_content[i] if i < len(right_content) else Paragraph("", body_style)
        content_data.append([[left_item], [right_item]])
    
    # Create table for layout
    content_table = Table(content_data, colWidths=[4*inch, 4*inch])
    content_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 1),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('GRID', (0, 0), (-1, -1), 0.2, colors.HexColor('#d3e0ea')),
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f9fbff')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#b0c4de')),
        ('INNERGRID', (0, 0), (-1, -1), 0.1, colors.HexColor('#e6edf5')),
    ]))
    elements.append(content_table)
    
    doc.build(elements)
    return output_path

def generate_pdf_report(data, output_path):
    """Generate a PDF report from JSON data."""
    groq_report = generate_report_with_groq(data, None)
    visualization_files = create_visualizations(data, groq_report)
    return create_pdf_report(groq_report, visualization_files, output_path)