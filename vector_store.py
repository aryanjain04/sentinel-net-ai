import chromadb
import json
import os

client = chromadb.PersistentClient(path="./chroma_db")
# Using separate collections for 'Expert Knowledge' and 'Live Logs'
kb_collection = client.get_or_create_collection(name="knowledge_base")

def ingest_kb(json_path):
    if not os.path.exists(json_path): return
    
    with open(json_path, 'r') as f:
        data = json.load(f)
    
    documents = [item['description'] for item in data]
    metadatas = [{"id": item['id'], "name": item['name']} for item in data]
    ids = [item['id'] for item in data]

    kb_collection.add(
        documents=documents,
        metadatas=metadatas,
        ids=ids
    )
    print(f"Ingested {len(ids)} MITRE techniques into KB.")

if __name__ == "__main__":
    ingest_kb("knowledge_base/rules.json")