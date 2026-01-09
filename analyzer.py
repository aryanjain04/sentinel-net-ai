import json
import os
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain
import chromadb
from dotenv import load_dotenv

# Load environment variables (API Key)
load_dotenv()

class TrafficAnalyzer:
    def __init__(self, db_path="./chroma_db"):
        """
        Initialize the Analysis Engine.
        1. Connects to the Vector Knowledge Base.
        2. Initializes the Gemini Pro LLM.
        """
        # 1. Connect to Knowledge Base (ChromaDB)
        self.chroma_client = chromadb.PersistentClient(path=db_path)
        self.kb_collection = self.chroma_client.get_or_create_collection(name="knowledge_base")

        # 2. Initialize LLM (Gemini 1.5 Pro via LangChain)
        api_key = os.getenv("GOOGLE_API_KEY")
        if not api_key:
            print("WARNING: GOOGLE_API_KEY not found in .env. LLM features will fail.")
        
        self.llm = ChatGoogleGenerativeAI(
            model="gemini-1.5-pro", 
            google_api_key=api_key,
            temperature=0.1, # Low temperature for factual, consistent analysis
            convert_system_message_to_human=True
        )

        # 3. Define the Prompt Template (The "Brain" logic)
        self.prompt_template = PromptTemplate(
            input_variables=["flow_desc", "context"],
            template="""
            You are a Senior Cybersecurity Analyst (SOC Tier 3). 
            Your job is to analyze network traffic flows and determine if they represent a security threat.

            ### OBSERVED TRAFFIC FLOW:
            {flow_desc}

            ### RELEVANT EXPERT KNOWLEDGE (MITRE ATT&CK):
            {context}

            ### ANALYSIS INSTRUCTIONS:
            1. Compare the Observed Traffic against the Expert Knowledge.
            2. Determine if the traffic matches any known attack signatures (like Port Scanning, DoS, C2).
            3. Ignore common background noise (like standard DNS to 8.8.8.8 or HTTPS to known safe IPs).
            4. Provide a Risk Score (0-100) where 0 is benign and 100 is critical.

            ### OUTPUT FORMAT (STRICT JSON):
            Return ONLY a valid JSON object. Do not include markdown formatting or explanations outside the JSON.
            {{
                "risk_score": <int>,
                "classification": "<string: Benign | Suspicious | Malicious>",
                "confidence": <string: Low | Medium | High>,
                "reasoning": "<string: Detailed explanation of why you made this decision>",
                "mitigation": "<string: Suggested action (e.g., Block IP, Inspect Payload)>"
            }}
            """
        )

        self.chain = self.prompt_template | self.llm

    def _flow_to_text(self, flow):
        """
        Semantic Transformation: Converts a raw dictionary flow to a natural language story.
        "Bridging the gap between Structured Data and Unstructured LLMs."
        """
        src = f"{flow.get('src_ip')}:{flow.get('src_port')}"
        dst = f"{flow.get('dst_ip')}:{flow.get('dst_port')}"
        
        # Fix mismatch: parser.py sends 'proto' (int), we want text
        proto_val = flow.get('protocol') or flow.get('proto')
        proto_map = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}
        if isinstance(proto_val, int):
            proto = proto_map.get(proto_val, str(proto_val))
        else:
            proto = str(proto_val) if proto_val else 'Unknown'

        # Fix mismatch: parser.py sends 'flags' (str "S,A"), we want list
        flags_val = flow.get('tcp_flags') or flow.get('flags')
        flags = []
        if isinstance(flags_val, list):
            flags = flags_val
        elif isinstance(flags_val, str) and flags_val:
            flags = flags_val.split(',')

        pkts = flow.get('packet_count', 0)
        bytes_ = flow.get('byte_count', 0)
        duration = flow.get('duration', 0)

        narrative = (
            f"A {proto} connection from {src} to {dst}. "
            f"Transferred {bytes_} bytes over {pkts} packets. "
            f"Duration was {duration:.2f} seconds. "
        )
        
        if flags:
            narrative += f"TCP Flags observed: {', '.join(flags)}."
        
        # Heuristic hints for the LLM
        if pkts > 100 and duration < 1:
            narrative += " (High velocity traffic detected)."
        if bytes_ == 0:
            narrative += " (Zero payload data detected)."
        
        return narrative

    def analyze_flow(self, flow_data):
        """
        The Core RAG Pipeline:
        1. Narrative Generation (Data -> Text)
        2. Retrieval (Text -> Context)
        3. Augmented Generation (Text + Context -> Analysis)
        """
        # Step 1: Narrative Generation
        flow_narrative = self._flow_to_text(flow_data)
        
        # Step 2: Context Retrieval (RAG)
        # Query ChromaDB for the 2 most similar attack descriptions
        results = self.kb_collection.query(
            query_texts=[flow_narrative],
            n_results=2
        )
        
        # Extract meaningful context texts
        if results and results['documents']:
            context_text = "\n".join(results['documents'][0])
        else:
            context_text = "No specific MITRE technique matched strongly."

        # Step 3: LLM Inference
        try:
            response_msg = self.chain.invoke({
                "flow_desc": flow_narrative,
                "context": context_text
            })
            
            # Parse the response content (it comes as an AIMessage object)
            response_text = response_msg.content.strip()
            
            # Clean up potential markdown formatting if the model slipped up
            response_text = response_text.replace("```json", "").replace("```", "")
            
            analysis_json = json.loads(response_text)
            
            # Add metadata back to the result for the dashboard
            analysis_json['flow_id'] = f"{flow_data.get('src_ip')}->{flow_data.get('dst_ip')}"
            return analysis_json

        except Exception as e:
            return {
                "risk_score": 0,
                "classification": "Error",
                "reasoning": f"Analysis failed: {str(e)}",
                "mitigation": "Check logs"
            }

if __name__ == "__main__":
    # Test Block
    print("Initializing Analyzer...")
    analyzer = TrafficAnalyzer()
    
    # Test File: Simulating a "Port Scan" flow
    # (High packets, zero bytes, short duration, SYN flag)
    test_flow = {
        "src_ip": "192.168.1.105",
        "src_port": 4444,
        "dst_ip": "10.0.0.1",
        "dst_port": 80,
        "protocol": "TCP",
        "packet_count": 50,
        "byte_count": 0,
        "duration": 0.5,
        "tcp_flags": ["SYN"]
    }
    
    print("\nRunning Test Analysis...")
    result = analyzer.analyze_flow(test_flow)
    print(json.dumps(result, indent=2))
