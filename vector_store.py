import chromadb
import json
import os
import numpy as np
from rank_bm25 import BM25Okapi

class HybridKnowledgeBase:
    def __init__(self, db_path="./chroma_db", rules_path="knowledge_base/rules.json"):
        """
        Hybrid Search Engine: Combines Semantic Search (ChromaDB) with Keyword Search (BM25).
        "Best specific context + Best conceptual match"
        """
        self.chroma_client = chromadb.PersistentClient(path=db_path)
        self.collection = self.chroma_client.get_or_create_collection(name="knowledge_base")
        
        # Load Data for BM25 (In-Memory Keyword Engine)
        self.documents = []
        self.metadatas = []
        
        if os.path.exists(rules_path):
            with open(rules_path, 'r') as f:
                data = json.load(f)
                self.documents = [item['description'] for item in data]
                self.metadatas = [{"id": item['id'], "name": item['name']} for item in data]
                
                # Tokenize for BM25
                tokenized_docs = [doc.lower().split(" ") for doc in self.documents]
                self.bm25 = BM25Okapi(tokenized_docs)
        else:
            print(f"⚠️ Warning: Rules file not found at {rules_path}. BM25 disabled.")
            self.bm25 = None

    def ingest_rules(self, rules_path="knowledge_base/rules.json"):
        # (Same ingestion logic as before, just wrapped)
        if not os.path.exists(rules_path): return
        with open(rules_path, 'r') as f:
            data = json.load(f)
        
        docs = [item['description'] for item in data]
        metas = [{"id": item['id'], "name": item['name']} for item in data]
        ids = [item['id'] for item in data]

        self.collection.add(documents=docs, metadatas=metas, ids=ids)
        print(f"✅ Ingested {len(ids)} rules into ChromaDB.")

    def search(self, query, top_k=3):
        """
        Performs Hybrid Search using Reciprocal Rank Fusion (RRF).
        """
        if not self.bm25:
            # Fallback to pure vector search if BM25 failed
            results = self.collection.query(query_texts=[query], n_results=top_k)
            return results['documents'][0] if results['documents'] else []

        # 1. Get Vector Results (Semantic)
        vector_results = self.collection.query(
            query_texts=[query], 
            n_results=top_k * 2 # Fetch more for re-ranking
        )
        # Flatten structure: list of docs
        vec_docs = vector_results['documents'][0] if vector_results['documents'] else []

        # 2. Get BM25 Results (Keyword)
        tokenized_query = query.lower().split(" ")
        bm25_docs = self.bm25.get_top_n(tokenized_query, self.documents, n=top_k * 2)

        # 3. Reciprocal Rank Fusion (Simple Version)
        # We value Vector and Keyword matches, prioritizing intersection
        
        # Simple Logic: Dedup and return top combined
        combined_results = []
        seen = set()
        
        # Interleave results (1 vec, 1 bm25, 1 vec...)
        max_len = max(len(vec_docs), len(bm25_docs))
        for i in range(max_len):
            if i < len(vec_docs):
                doc = vec_docs[i]
                if doc not in seen:
                    combined_results.append(doc)
                    seen.add(doc)
            if i < len(bm25_docs):
                doc = bm25_docs[i]
                if doc not in seen:
                    combined_results.append(doc)
                    seen.add(doc)
            
            if len(combined_results) >= top_k:
                break
                
        return combined_results[:top_k]

if __name__ == "__main__":
    # Test Ingestion and Search
    kb = HybridKnowledgeBase()
    kb.ingest_rules()
    
    print("\n🔍 Testing Hybrid Search: 'Syn Flood'")
    hits = kb.search("Many short lived TCP connections with SYN flag set")
    for i, hit in enumerate(hits):
        print(f"{i+1}. {hit[:100]}...")