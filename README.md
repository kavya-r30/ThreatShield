# ThreatShield: AI-Powered Malware Analysis Platform 

**ThreatShield** is a robust and extensible malware analysis platform designed for security professionals, malware researchers, and system administrators. It combines **static** and **dynamic analysis techniques** with **machine learning** to detect, analyze, and report malicious behavior across a wide range of file formats.

ThreatShield aims to simplify threat detection workflows while providing deep and explainable insights into suspicious files. Whether you are analyzing a Windows executable or a malicious macro in a document, ThreatShield delivers the tools you need.

---

## Key Features

### 1. Multi-format Support

ThreatShield supports comprehensive analysis for a variety of file types, including:

- **PE files**: Windows executables and dynamic link libraries (`.exe`, `.dll`)
- **PDF documents**: Scans for embedded scripts, suspicious objects, JavaScript, and obfuscation
- **Microsoft Office files**: Analyzes `.doc`, `.docx`, `.xls`, `.xlsx`, `.ppt`, and `.pptx` for macros, scripts, and exploits
- **Scripts**: Includes JavaScript (`.js`), Python (`.py`), VBScript (`.vbs`), and batch files (`.bat`)
- **Android packages**: Analyzes APK files for permissions, components, and potential malicious behavior
- **Archives**: Supports `.zip`, `.rar`, and `.7z` for unpacking and recursively analyzing contents
- **Text and configuration files**: Analyzes `.json`, `.xml`, and other text formats for embedded indicators

### 2. Static Analysis

ThreatShield performs deep inspection of files without execution. Key static analysis capabilities include:

- Header and metadata inspection
- Disassembly and string extraction
- Macro and embedded object detection
- Entropy and obfuscation scoring
- Signature-based rule matching (YARA, ClamAV, etc.)

### 3. Dynamic Analysis

Dynamic or behavioral analysis is performed in a controlled sandbox environment, capturing real-time interactions and changes.

### 4. AI-Powered Insights

Machine learning models are integrated to:

- Classify files as benign, suspicious, or malicious
- Detect known malware families based on behavioral patterns
- Cluster similar threats for correlation and pattern discovery
- Provide contextual explanations for anomalies

### 5. Interactive Chatbot Assistant

An integrated natural language assistant enables users to:

- Ask questions about a file’s behavior and components
- Query definitions of suspicious activities
- Receive guided summaries of analysis results

### 6. Voice Assistant Integration

ThreatShield supports hands-free interaction through voice commands, ideal for accessibility or multitasking in operational environments.

### 7. Detailed and Visual Reports

Analysis results are compiled into structured reports, featuring all results that can be exported as professional PDF reports for documentation, audits, or sharing with stakeholders.

### 8. Command-Line Interface (CLI) Tool

ThreatShield includes a powerful CLI tool for streamlined malware analysis directly from the terminal. Key commands include:
- `malware-detect <filename>`: Scans a specified file for malware and outputs a detailed report in the terminal.
- `malware-detect`: Launches a user-friendly UI for interactive malware analysis.
- `malware-detect --threatshield`: Opens the ThreatShield web interface in the default browser for full platform access.

## To use the CLI tool
- Download the .exe file from [here](https://drive.google.com/file/d/1RAVTcn4QLDRnRPI7MSc9wbQPDIkiEWzQ/view?usp=sharing)
- Place the Downloaded exe file in a desired Folder.
- Add the Path of the Folder to the System Environment Variables and then the CLI tool is good to go.
---

## Tech Stack

| Category     | Technologies                                                                                                                                                         |
|--------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Framework    | [![Flask](https://img.shields.io/badge/flask-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/) [![Next.js](https://img.shields.io/badge/next.js-000000?style=for-the-badge&logo=next.js&logoColor=white)](https://nextjs.org/)                             |
| Language     | [![Python](https://img.shields.io/badge/python-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/) [![TypeScript](https://img.shields.io/badge/typescript-3178C6?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)               |
| Libraries    | [![pefile](https://img.shields.io/badge/pefile-4B8BBE?style=for-the-badge&logo=python&logoColor=white)](https://github.com/erocarrera/pefile) [![yara-python](https://img.shields.io/badge/yara--python-FF4C4C?style=for-the-badge&logo=python&logoColor=white)](https://github.com/VirusTotal/yara-python) [![langchain](https://img.shields.io/badge/langchain-006400?style=for-the-badge&logo=python&logoColor=white)](https://github.com/langchain-ai/langchain) [![scikit-learn](https://img.shields.io/badge/scikit--learn-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)](https://scikit-learn.org/) [![pdfminer.six](https://img.shields.io/badge/pdfminer.six-003153?style=for-the-badge&logo=python&logoColor=white)](https://github.com/pdfminer/pdfminer.six) [![python-docx](https://img.shields.io/badge/python--docx-2B579A?style=for-the-badge&logo=python&logoColor=white)](https://github.com/python-openxml/python-docx) [![TailwindCSS](https://img.shields.io/badge/tailwindcss-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white)](https://tailwindcss.com/) [![shadcn/ui](https://img.shields.io/badge/shadcn--ui-1E1E1E?style=for-the-badge&logo=react&logoColor=white)](https://ui.shadcn.com/)  [![Lucide React](https://img.shields.io/badge/lucide--react-000000?style=for-the-badge&logo=react&logoColor=white)](https://lucide.dev/) |

---

## Project Structure
```
threatshield/
├── backend/
│   ├── app.py
│   ├── model.py
│   ├── chat.py
│   ├── report.py
│   ├── pdf_models/
│   └── ...
│
├── frontend/
│   ├── app/
│   ├── components/
│   ├── lib/
│   └── public/
│
├── cli_tool/
│   ├── malware_detector/
│   │   ├── __init__.py
│   │   ├── cli.py
│   │   ├── malware_detector.py
│   │   └── ui.py
│   ├── setup.py
│   └── README.md
```
---

## Contributors

- **Kavya Rambhia** - [GitHub Profile](https://github.com/kavya-r30)
- **Dhruv Panchal** - [GitHub Profile](https://github.com/dhruvp18)
- **Swayam Shah** - [GitHub Profile](https://github.com/sonu0305)
- **Viraj Vora** - [GitHub Profile](https://github.com/viraj200524)
