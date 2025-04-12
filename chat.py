from langchain_groq import ChatGroq
from langchain.prompts import PromptTemplate, ChatPromptTemplate
from langchain.output_parsers import StructuredOutputParser, ResponseSchema
from langchain.schema import StrOutputParser
from langchain.schema.runnable import RunnablePassthrough
import os
import json
from typing import Dict, Any, Optional, List, Union

class MalwareAnalysisChatbot:
    def __init__(self, api_key: Optional[str] = None):
        """Initialize the Malware Analysis Chatbot.
        
        Args:
            api_key: Groq API key (defaults to GROQ_API_KEY environment variable)
        """
        self.api_key = "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"
        if not self.api_key:
            raise ValueError("Groq API key is required. Set it via GROQ_API_KEY environment variable or pass it directly.")
        
        # Initialize the Groq LLM
        self.llm = ChatGroq(
            api_key=self.api_key,
            model="llama3-70b-8192",  # Use Llama 3 70B model
            temperature=0.2,  # Low temperature for more deterministic outputs
            max_tokens=4096
        )
        
        # Setup the report generation template
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
        
        # Setup the general chat template
        self.chat_template = ChatPromptTemplate.from_template("""
            You are a cybersecurity analyst specializing in malware detection and analysis. 
            Provide accurate, helpful information about malware, security threats, and best practices for protection.
            
            If asked about specific file analysis, explain that you need the analysis JSON data to provide detailed insights.
            
            User question: {question}
            
            Answer in a clear, helpful, and informative manner. If the question is outside your expertise, acknowledge 
            your limitations and suggest appropriate resources or alternative approaches.
        """)
        
        # Create the general chatbot chain
        self.chat_chain = (
            {"question": RunnablePassthrough()}
            | self.chat_template
            | self.llm
            | StrOutputParser()
        )
        
        # Create the report generation chain
        self.report_chain = (
            {"json_data": RunnablePassthrough()}
            | self.report_template
            | self.llm
            | StrOutputParser()
        )
    
    def generate_report_from_json(self, json_data: Union[Dict, str]) -> str:
        """Generate a human-readable report from JSON analysis data.
        
        Args:
            json_data: A dictionary or JSON string containing malware analysis data
            
        Returns:
            str: A formatted report analyzing the malware data
        """
        # Ensure json_data is in string format
        if isinstance(json_data, dict):
            json_data = json.dumps(json_data, indent=2)
        
        try:
            return self.report_chain.invoke(json_data)
        except Exception as e:
            return f"Error generating report: {str(e)}"
    
    def ask(self, question: str) -> str:
        """Ask a general question about malware or cybersecurity.
        
        Args:
            question: The user's question about malware or security
            
        Returns:
            str: The chatbot's response
        """
        try:
            return self.chat_chain.invoke(question)
        except Exception as e:
            return f"Error processing your question: {str(e)}"


class JSONReportChatbot:
    """A chatbot that specializes in handling and explaining JSON malware reports."""
    
    def __init__(self, api_key: Optional[str] = None):
        """Initialize the JSON Report Chatbot.
        
        Args:
            api_key: Groq API key (defaults to GROQ_API_KEY environment variable)
        """
        self.api_key = api_key or os.environ.get("GROQ_API_KEY")
        self.base_chatbot = MalwareAnalysisChatbot(api_key=self.api_key)
        
        # Add specialized response schemas for structured output
        self.response_schemas = [
            ResponseSchema(name="summary", description="A brief summary of the malware analysis findings"),
            ResponseSchema(name="threat_level", description="The assessed threat level (Low, Medium, High, Critical)"),
            ResponseSchema(name="key_indicators", description="List of key malicious indicators found in the analysis"),
            ResponseSchema(name="recommendations", description="Security recommendations based on the findings")
        ]
        
        self.output_parser = StructuredOutputParser.from_response_schemas(self.response_schemas)
        
        # Setup a specialized JSON analysis template with structured output
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
        
        # Create structured analysis chain
        self.structured_analysis_chain = (
            self.json_analysis_template 
            | self.base_chatbot.llm 
            | self.output_parser
        )
    
    def analyze_json_report(self, json_data: Union[Dict, str]) -> Dict[str, Any]:
        """Generate a structured analysis of a JSON malware report.
        
        Args:
            json_data: A dictionary or JSON string containing malware analysis data
            
        Returns:
            Dict[str, Any]: A structured analysis with summary, threat level, key indicators, and recommendations
        """
        # Ensure json_data is in string format
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
        """Generate a human-readable report from JSON analysis data.
        
        Args:
            json_data: A dictionary or JSON string containing malware analysis data
            
        Returns:
            str: A formatted report analyzing the malware data
        """
        return self.base_chatbot.generate_report_from_json(json_data)
    
    def ask(self, question: str) -> str:
        """Ask a general question about malware or cybersecurity.
        
        Args:
            question: The user's question about malware or security
            
        Returns:
            str: The chatbot's response
        """
        return self.base_chatbot.ask(question)
