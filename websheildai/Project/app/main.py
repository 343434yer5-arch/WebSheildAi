from fastapi import FastAPI, HTTPException, Request, Depends
from pydantic import BaseModel
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
import uvicorn
from database import SessionLocal, engine
import models
from fastapi.templating import Jinja2Templates
from datetime import datetime
import sys
import os
import traceback

# Импорты без "app." если запускаем из папки app
try:
    from ml_engine import ThreatDetector
    from response_engine import ResponseManager
except ImportError:
    from .ml_engine import ThreatDetector
    from .response_engine import ResponseManager

models.Base.metadata.create_all(bind=engine)

app = FastAPI()

templates = Jinja2Templates(directory="templates")
detector = ThreatDetector()

class TrafficLog(BaseModel):
    timestamp: str
    source_ip: str
    request_url: str
    user_agent: str
    method: str
    payload: str = ""

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get("/")
async def home(request: Request):
    return templates.TemplateResponse(
        "index.html",
        {"request": request}
    )

@app.get("/api/v1/dashboard")
async def dashboard(request: Request, db: Session = Depends(get_db)):
    incidents = db.query(models.Record).all()
    ips = set()
    k = 0
    for i in db.query(models.Record.ip).all():
        if i not in ips:
            ips.add(i)
            k += 1
    return templates.TemplateResponse(
        'dashboard.html',
        {"request": request, "total_requests": db.query(models.Record).count(),
         'recent_requests': db.query(models.Record).count(), 'unique_ips': k , 'analyze_requests': incidents}
    )

@app.get("/api/v1/dashboard/incidents")
async def get_dashboard_data(request: Request, db: Session = Depends(get_db)):
    incidents = db.query(models.Record).all()
    return templates.TemplateResponse(
        "incidents.html",
        {"request": request, "records": incidents}
    )


@app.post("/api/v1/analyze")
async def analyze_traffic(log: TrafficLog, db: Session = Depends(get_db)):
    try:
        # 1. Анализ
        scan_target = f"{log.request_url} {log.payload}"
        result = detector.analyze(scan_target)

        actions = []
        if result["is_threat"]:
            # 2. Реакция
            actions = ResponseManager.execute_response(
                incident_type=result["type"],
                source_ip=log.source_ip,
                risk_score=result["confidence"]
            )
            # 3. Сохранение (превращаем время в строку сразу)
            incid =  models.Record()
            incid.type = result['type']
            incid.ip = log.source_ip
            incid.request_url = log.request_url
            incid.user_agent = log.user_agent
            incid.method = log.method
            incid.payload = log.payload
            incid.confidence = result['confidence']
            incid.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            db.add(incid)
            db.commit()

        return {
            "status": "BLOCKED" if result["is_threat"] else "ALLOWED",
            "threat_type": result["type"],
            "confidence": result["confidence"],
            "actions": actions
        }
    except Exception as e:
        # Если что-то сломалось, мы увидим это в терминале сервера!
        print("!!! ОШИБКА ВНУТРИ СЕРВЕРА !!!")
        print(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))

app.mount("/img", StaticFiles(directory="static/img"), name="img")

if __name__ == '__main__':
    uvicorn.run('main:app', host='127.0.0.1', port=8080)