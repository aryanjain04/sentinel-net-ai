import os
import sys
import pandas as pd
from dotenv import load_dotenv

# Internal modules
from parser import process_pcap_to_flows_stream
from analyzer import TrafficAnalyzer

# Protocol mapping for better narrative
PROTO_MAP = {
    6: "TCP",
    17: "UDP",
    1: "ICMP"
}

def get_protocol_name(proto_num):
    return PROTO_MAP.get(proto_num, str(proto_num))

def heuristic_is_suspicious(flow):
    """
    Simple filter to skip obviously benign traffic to save LLM costs.
    Returns True if flow looks interesting enough to analyze.
    """
    # 1. Skip standard DNS traffic to trusted resolvers
    # (Google DNS, Cloudflare) - assuming low volume
    trusted_dns = ['8.8.8.8', '8.8.4.4', '1.1.1.1']
    if (flow['dst_port'] == 53 or flow['src_port'] == 53) and \
       (flow['dst_ip'] in trusted_dns or flow['src_ip'] in trusted_dns) and \
       flow['packet_count'] < 10:
        return False

    # 2. Skip local loopback (unless you want to debug it)
    if flow['src_ip'] == '127.0.0.1' or flow['dst_ip'] == '127.0.0.1':
        return False

    # 3. INTERESTING: High packet count, low duration (flooding)
    if flow['packet_count'] > 50 and flow['duration'] < 1.0:
        return True
    
    # 4. INTERESTING: Zero byte payload features (often scanning)
    if flow['byte_count'] == 0 and flow['packet_count'] > 3:
        return True

    # 5. INTERESTING: Non-standard high ports involved
    if flow['dst_port'] > 10000 or flow['src_port'] > 10000:
        return True

    # Default: Analyze it if we aren't sure
    return True

def main():
    # 1. Setup
    load_dotenv()
    if not os.getenv("GOOGLE_API_KEY"):
        print("❌ Error: GOOGLE_API_KEY not found in .env file.")
        print("Please create a .env file with your API key.")
        return

    pcap_file = "sample.pcap"
    if len(sys.argv) > 1:
        pcap_file = sys.argv[1]

    if not os.path.exists(pcap_file):
        print(f"❌ Error: File {pcap_file} not found.")
        print("Run 'python generate_sample.py' to create a test file.")
        return

    print(f"🔍 Parsing {pcap_file}...")
    df_flows = process_pcap_to_flows_stream(pcap_file)
    print(f"✅ Extracted {len(df_flows)} flows.")

    print("🧠 Initializing AI Analyst...")
    try:
        analyzer = TrafficAnalyzer()
    except Exception as e:
        print(f"❌ Failed to init analyzer: {e}")
        return

    results = []
    print("\n🚀 Starting Analysis Pipeline (Heuristic Filter -> RAG -> LLM)\n")
    
    for index, row in df_flows.iterrows():
        # Convert row to dictionary and normalize types
        flow = row.to_dict()
        
        # Normalize fields for analyzer
        flow['tcp_flags'] = flow['flags'].split(',') if flow['flags'] else []
        flow['protocol'] = get_protocol_name(flow['proto'])
        
        # Step 1: Heuristic Filter
        if not heuristic_is_suspicious(flow):
            print(f"Skipping Flow {index}: {flow['src_ip']} -> {flow['dst_ip']} (Heuristic: Benign)")
            continue

        print(f"⚡ Analyzing Flow {index}: {flow['src_ip']} -> {flow['dst_ip']} ({flow['protocol']})...")
        
        # Step 2: Agentic Analysis
        analysis = analyzer.analyze_flow(flow)
        
        # Print Result
        score = analysis.get('risk_score', 0)
        classification = analysis.get('classification', 'Unknown')
        print(f"   -> Result: [{score}/100] {classification}")
        print(f"   -> Reasoning: {analysis.get('reasoning')}")
        print("-" * 50)
        
        results.append(analysis)

    # Save detailed results
    if results:
        pd.DataFrame(results).to_json("analysis_report.json", orient="records", indent=2)
        print(f"\n✅ Analysis Complete. Full report saved to 'analysis_report.json'.")
    else:
        print("\n✅ Analysis Complete. No threats detected.")

if __name__ == "__main__":
    main()
