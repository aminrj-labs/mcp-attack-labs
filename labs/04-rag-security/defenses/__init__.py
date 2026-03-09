# RAG Security — Defense Layers
# Each module implements one layer of the defense stack.
#
#  Layer 1  sanitize_ingestion.py        — strip injection patterns at ingest time
#  Layer 2  access_controlled_retrieval.py — metadata-filtered ChromaDB queries
#  Layer 3  hardened_prompt.py           — explicit instruction / context separation
#  Layer 4  output_monitor.py            — regex + pattern scan of generated text
#  Layer 5  embedding_anomaly_detection.py — cosine cluster analysis at ingest time
