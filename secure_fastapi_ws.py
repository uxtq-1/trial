# secure_ws_backend.py
# Purpose: FastAPI backend for OPS Security Disclosure
# - Accepts WebSocket connections from security-socket.js
# - Receives form metadata + file, scans for malware/macros (open-source tools: oletools for DOC/DOCX, PyPDF2/pdfminer/pdf.js for PDF)
# - If clean: notifies client, ready for encryption/upload; if infected: blocks and alerts client

import os
import tempfile
import asyncio
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from starlette.websockets import WebSocketState

import oletools.olevba as olevba  # For DOC/DOCX macro detection
import PyPDF2  # For basic PDF analysis (optionally: pdfminer or custom rules)

app = FastAPI()

@app.websocket("/secure/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    meta = None
    tmp_file_path = None

    try:
        # 1. Receive metadata (JSON) from client
        meta_json = await websocket.receive_text()
        meta = eval(meta_json)  # For demo only; use json.loads(meta_json) in production!
        filename = meta["filename"]

        # 2. Receive the file data (ArrayBuffer from JS)
        data = await websocket.receive_bytes()
        # Save to temp file for scanning
        with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(filename)[-1]) as tmpf:
            tmpf.write(data)
            tmp_file_path = tmpf.name

        # 3. Scan the file (malware/macros)
        await websocket.send_text('{"status": "scanning"}')
        is_malicious = False

        # DOC/DOCX: Check for macros with oletools
        if filename.lower().endswith(('.doc', '.docx')):
            vba = olevba.VBA_Parser(tmp_file_path)
            if vba.detect_vba_macros():
                is_malicious = True

        # PDF: Check for JS/launch actions (PyPDF2 basic example)
        elif filename.lower().endswith('.pdf'):
            with open(tmp_file_path, "rb") as f:
                reader = PyPDF2.PdfReader(f)
                for page in reader.pages:
                    if "/JavaScript" in page or "/JS" in page or "/AA" in page:
                        is_malicious = True
                        break

        # 4. Return result
        if is_malicious:
            await websocket.send_text('{"status": "infected"}')
        else:
            await websocket.send_text('{"status": "clean"}')

    except Exception as e:
        await websocket.send_text(f'{{"status": "error", "msg": "{str(e)}"}}')
    finally:
        # Clean up temp file
        if tmp_file_path and os.path.exists(tmp_file_path):
            os.remove(tmp_file_path)
        await websocket.close()
