import os
import json
import logging
from dotenv import load_dotenv
from typing import Dict, Any, Optional, List, Union
from langchain_groq import ChatGroq
from langchain.prompts import PromptTemplate, ChatPromptTemplate
from langchain.output_parsers import StructuredOutputParser, ResponseSchema
from langchain.schema import StrOutputParser
from langchain.schema.runnable import RunnablePassthrough

load_dotenv()

class MalwareAnalysisChatbot:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = os.getenv("API_KEY_CHAT")
        if not self.api_key:
            raise ValueError("Environment variable not passed.")
        
        self.llm = ChatGroq(
            api_key=self.api_key,
            model="llama3-70b-8192",
            temperature=0.2,
            max_tokens=4096
        )
        
        self.report_template = ChatPromptTemplate.from_template("""
            You are a cybersecurity expert specializing in malware analysis. You've been provided with a JSON report 
            containing analysis data about a potentially malicious file. Generate a comprehensive, human-readable report 
            based on this data.

            The report should be structured, clearly explaining the findings and providing a risk assessment. 
            Include recommendations based on the threat level detected.

            JSON Analysis Data:
            {json_data}

            Format your response as a structured report with the following sections:
            1. Summary of Findings
            2. Technical Details
            3. Risk Assessment
            4. Recommendations
            
            Be specific and refer to actual data points from the JSON analysis.
        """)
        
        self.chat_template = ChatPromptTemplate.from_template("""
            You are a cybersecurity analyst specializing in malware detection and analysis. 
            Provide accurate, helpful information about malware, security threats, and best practices for protection.
            
            If asked about specific file analysis, explain that you need the analysis JSON data to provide detailed insights.
            
            User question: {question}
            
            Answer in a clear, helpful, and informative manner. If the question is outside your expertise, acknowledge 
            your limitations and suggest appropriate resources or alternative approaches.
        """)
        
        self.chat_chain = (
            {"question": RunnablePassthrough()}
            | self.chat_template
            | self.llm
            | StrOutputParser()
        )
        
        self.report_chain = (
            {"json_data": RunnablePassthrough()}
            | self.report_template
            | self.llm
            | StrOutputParser()
        )
    
    def generate_report_from_json(self, json_data: Union[Dict, str]) -> str:
        if isinstance(json_data, dict):
            json_data = json.dumps(json_data, indent=2)
        
        try:
            return self.report_chain.invoke(json_data)
        except Exception as e:
            return f"Error generating report: {str(e)}"
    
    def ask(self, question: str) -> str:
        try:
            return self.chat_chain.invoke(question)
        except Exception as e:
            return f"Error processing your question: {str(e)}"


class JSONReportChatbot:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("GROQ_API_KEY")
        self.base_chatbot = MalwareAnalysisChatbot(api_key=self.api_key)
        
        self.response_schemas = [
            ResponseSchema(name="summary", description="A brief summary of the malware analysis findings"),
            ResponseSchema(name="threat_level", description="The assessed threat level (Low, Medium, High, Critical)"),
            ResponseSchema(name="key_indicators", description="List of key malicious indicators found in the analysis"),
            ResponseSchema(name="recommendations", description="Security recommendations based on the findings")
        ]
        
        self.output_parser = StructuredOutputParser.from_response_schemas(self.response_schemas)
        
        self.json_analysis_template = PromptTemplate(
            template="""
            You are a cybersecurity expert analyzing malware detection results.
            
            Analyze the following JSON malware analysis report and provide a structured assessment:
            
            {json_data}
            
            {format_instructions}
            """,
            input_variables=["json_data"],
            partial_variables={"format_instructions": self.output_parser.get_format_instructions()}
        )
        
        self.structured_analysis_chain = (
            self.json_analysis_template 
            | self.base_chatbot.llm 
            | self.output_parser
        )
    
    def analyze_json_report(self, json_data: Union[Dict, str]) -> Dict[str, Any]:
        if isinstance(json_data, dict):
            json_data = json.dumps(json_data, indent=2)
        
        try:
            return self.structured_analysis_chain.invoke({"json_data": json_data})
        except Exception as e:
            return {
                "error": str(e),
                "summary": "Error analyzing report",
                "threat_level": "Unknown",
                "key_indicators": ["Analysis failed"],
                "recommendations": ["Retry analysis or contact support"]
            }
    
    def generate_report(self, json_data: Union[Dict, str]) -> str:
        return self.base_chatbot.generate_report_from_json(json_data)
    
    def ask(self, question: str) -> str:
        return self.base_chatbot.ask(question)
