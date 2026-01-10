import chromadb
import json
import os
from rank_bm25 import BM25Okapi
from sentence_transformers import SentenceTransformer

class HybridKnowledgeBase:
    def __init__(self, db_path="./chroma_db", rules_path="knowledge_base/rules.json"):
        """
        Hybrid Search Engine: Combines Semantic Search (ChromaDB) with Keyword Search (BM25).
        This provides context for both 'behavior' (vectors) and 'specifics' (keywords).
        """
        self.chroma_client = chromadb.PersistentClient(path=db_path)
        # Use the same model as the analyzer for mathematical consistency
        self.embedder = SentenceTransformer("all-MiniLM-L6-v2")
        self.collection = self.chroma_client.get_or_create_collection(name="knowledge_base")
        
        self.documents = []
        self.metadatas = []
        self.bm25 = None
        
        # Load Data for BM25 (Keyword Engine)
        if os.path.exists(rules_path):
            with open(rules_path, 'r') as f:
                data = json.load(f)
                self.documents = [item['description'] for item in data]
                self.metadatas = [{"id": item['id'], "name": item['name']} for item in data]
                
                # Tokenize for BM25 keyword matching
                tokenized_docs = [doc.lower().split(" ") for doc in self.documents]
                self.bm25 = BM25Okapi(tokenized_docs)
        else:
            print(f"⚠️ Warning: Rules file not found at {rules_path}")

    def ensure_ingested(self, json_path="knowledge_base/rules.json"):
        """Ensures ChromaDB has at least some KB docs."""
        try:
            if self.collection.count() == 0:
                self.ingest_kb(json_path=json_path)
        except Exception:
            # If count() is unavailable or DB is read-only, don't hard fail.
            return

    def ingest_kb(self, json_path="knowledge_base/rules.json"):
        """Ingests and embeds the MITRE rules into ChromaDB."""
        if not os.path.exists(json_path): return
        
        with open(json_path, 'r') as f:
            data = json.load(f)
        
        docs = [item['description'] for item in data]
        metas = [{"id": item['id'], "name": item['name']} for item in data]
        ids = [item['id'] for item in data]
        
        # Generate embeddings locally
        embeddings = self.embedder.encode(docs).tolist()

        self.collection.upsert(
            documents=docs,
            metadatas=metas,
            ids=ids,
            embeddings=embeddings
        )
        print(f"Successfully ingested {len(ids)} MITRE techniques.")

    def hybrid_search(self, query, top_k=2):
        """
        Performs both Vector and Keyword search, then merges results.
        """
        # 1. Semantic Search (Vector)
        vec_docs = []
        try:
            query_emb = self.embedder.encode([query]).tolist()
            v_results = self.collection.query(query_embeddings=query_emb, n_results=top_k)
            vec_docs = (v_results.get('documents') or [[]])[0]
        except Exception:
            vec_docs = []

        # 2. Keyword Search (BM25)
        bm25_docs = []
        if self.bm25 is not None and self.documents:
            tokenized_query = query.lower().split(" ")
            bm25_docs = self.bm25.get_top_n(tokenized_query, self.documents, n=top_k)

        # 3. Simple Interleaving (Merging for the LLM)
        combined = []
        seen = set()
        for doc_list in [vec_docs, bm25_docs]:
            for doc in doc_list:
                if doc not in seen:
                    combined.append(doc)
                    seen.add(doc)
        
        return combined[:top_k]

if __name__ == "__main__":
    kb = HybridKnowledgeBase()
    kb.ingest_kb()