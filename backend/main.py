from pathlib import Path

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
import os
import shutil

from analyzer import analyze_pcap

app = FastAPI(title="PCAP Analyzer")

BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = BASE_DIR.parent / "frontend"
UPLOAD_DIR = BASE_DIR / "uploads"

os.makedirs(UPLOAD_DIR, exist_ok=True)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.post("/upload")
def upload_pcap(file: UploadFile = File(...)):
    if not (file.filename.endswith(".pcap") or file.filename.endswith(".pcapng")):
        raise HTTPException(status_code=400, detail="Only .pcap or .pcapng files are allowed")

    file_path = os.path.join(UPLOAD_DIR, file.filename)

    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    results = analyze_pcap(file_path)

    return {
        "filename": file.filename,
        "status": "uploaded successfully",
        "analysis": results
    }


app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")