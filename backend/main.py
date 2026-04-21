from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import os
import shutil

from analyzer import analyze_pcap

app = FastAPI(title="PCAP Analyzer")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)


@app.get("/")
def root():
    return {"message": "PCAP Analyzer backend is running"}


@app.post("/upload")
def upload_pcap(file: UploadFile = File(...)):
    if not file.filename.endswith(".pcap"):
        raise HTTPException(status_code=400, detail="Only .pcap files are allowed")

    file_path = os.path.join(UPLOAD_DIR, file.filename)

    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    results = analyze_pcap(file_path)

    return {
        "filename": file.filename,
        "status": "uploaded successfully",
        "analysis": results
    }