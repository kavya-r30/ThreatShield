import os
import json
import logging
from dotenv import load_dotenv
from langchain_groq import ChatGroq
from langchain.schema import StrOutputParser
from langchain_core.prompts import PromptTemplate

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
logging.getLogger('pdfminer.pdfpage').setLevel(logging.ERROR)
logging.getLogger("api.groq").setLevel(logging.WARNING)

load_dotenv()
api_key = os.getenv("API_KEY_REPORT")

if not api_key:
    raise ValueError("API_KEY_REPORT key not provided.")

model = ChatGroq(
    model="llama-3.3-70b-versatile",
    api_key=api_key
)

def generate_human_readable_report(analysis_json):
    prompt_template = PromptTemplate.from_template("""
    You are a cybersecurity analyst. A malware analysis has been completed on a file. Your task is to create a clear, structured, and professional report based on the following JSON input.

    Here is the analysis data:

    ```json
    {analysis_json}
                                                    
    Create a detailed human-readable report with the following sections:
    File Overview: Include file name and type.
    Malicious Assessment: Clearly state whether the file is malicious, along with the confidence level and risk rating.
    Indicators of Compromise (IOCs): List each indicator with its type, description, and severity.
    Recommended Mitigations: Provide any recommended actions or precautions for handling the file.
    Summary Conclusion: Provide a short paragraph summarizing the overall assessment and any next steps.
    Use bullet points or numbered lists where appropriate, and ensure the report is easy to read and professional in tone. """)

    try:
        report_chain = prompt_template | model | StrOutputParser()
        report = report_chain.invoke({"analysis_json":json.dumps(analysis_json, indent=2)})
        return report
    except Exception as e:
        logger.error(f"Error generating human-readable report: {str(e)}")
        return "An error occurred while generating the human-readable report."