#!/usr/bin/env python3
"""
SeeVee Enhanced API Server for Web Deployment
"""

import os
import sys
import time
from datetime import datetime
from typing import List, Optional, Dict, Any, Union
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Query, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import uvicorn

# Import from the main seevee module
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from seevee import (
    get_cve_info, get_cwe_info, get_cvss_details, analyze_cvss_risk, 
    update_database, update_cwe_database, CVEDatabase, format_duration
)


# Configuration
class Config:
    API_KEY = os.getenv("SEEVEE_API_KEY", "seevee-default-key-change-me")
    CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*").split(",")
    UPDATE_DB_ON_STARTUP = os.getenv("UPDATE_DB_ON_STARTUP", "false").lower() == "true"
    ENVIRONMENT = os.getenv("ENVIRONMENT", "production")
    PORT = int(os.getenv("PORT", 8000))
    HOST = os.getenv("HOST", "0.0.0.0")


# Authentication
def verify_api_key(x_api_key: str = Header(None)) -> bool:
    if x_api_key != Config.API_KEY:
        raise HTTPException(
            status_code=401,
            detail="Invalid API key",
            headers={"X-API-Key": "required"},
        )
    return True


# Pydantic models
class CVERequest(BaseModel):
    cve_ids: List[str] = Field(..., description="List of CVE IDs to lookup")
    include_cvss_details: bool = Field(False, description="Include detailed CVSS components")
    include_risk_analysis: bool = Field(False, description="Include risk analysis")
    include_references: bool = Field(True, description="Include reference URLs")

class CWERequest(BaseModel):
    cwe_ids: List[Union[str, int]] = Field(..., description="List of CWE IDs to lookup")

class DatabaseStats(BaseModel):
    cve_count: int
    cwe_count: int
    database_size_mb: float
    last_updated: Optional[str]
    environment: str


# Global state
app_state = {
    "startup_time": None,
    "last_db_update": None,
    "update_in_progress": False
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    app_state["startup_time"] = datetime.now()
    print("🚀 Starting SeeVee Web API Server...")
    
    # Start database update in background to not block startup
    if Config.UPDATE_DB_ON_STARTUP and not app_state["update_in_progress"]:
        print("📊 Scheduling database update...")
        import threading
        
        def update_db_background():
            try:
                app_state["update_in_progress"] = True
                print("📊 Starting background database update...")
                update_cwe_database()
                # Quick update for cloud deployment
                current_year = datetime.now().year
                update_database(years=[current_year, current_year - 1], include_modified=True)
                app_state["last_db_update"] = datetime.now()
                print("✅ Background database update completed")
            except Exception as e:
                print(f"❌ Background database update failed: {e}")
            finally:
                app_state["update_in_progress"] = False
        
        # Start update in background thread
        db_thread = threading.Thread(target=update_db_background, daemon=True)
        db_thread.start()
        print("📊 Database update started in background")
    
    print("🟢 SeeVee API Server is ready!")
    yield
    print("👋 Shutting down SeeVee Web API Server...")


# Initialize FastAPI app
app = FastAPI(
    title="SeeVee Web API",
    description="CVE and CWE Vulnerability Information API",
    version="1.0.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=Config.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


def get_database_stats() -> DatabaseStats:
    """Get database statistics"""
    try:
        db = CVEDatabase()
        
        # Get CVE count
        cve_count = 0
        import sqlite3
        if db.db_path.exists():
            with sqlite3.connect(db.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM cve_data")
                result = cursor.fetchone()
                cve_count = result[0] if result else 0
        
        # Get CWE count  
        cwe_count = db.get_cwe_count()
        
        # Get database file size
        db_size = 0
        if db.db_path.exists():
            db_size = db.db_path.stat().st_size / (1024 * 1024)  # MB
        
        return DatabaseStats(
            cve_count=cve_count,
            cwe_count=cwe_count,
            database_size_mb=round(db_size, 2),
            last_updated=app_state["last_db_update"].isoformat() if app_state["last_db_update"] else None,
            environment=Config.ENVIRONMENT
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get database stats: {str(e)}")


# API Routes
@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "service": "SeeVee Web API", 
        "version": "1.0.0",
        "description": "CVE and CWE Vulnerability Information API",
        "environment": Config.ENVIRONMENT,
        "authentication": "X-API-Key header required"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    uptime = (datetime.now() - app_state["startup_time"]).total_seconds() if app_state["startup_time"] else 0
    
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "uptime_seconds": uptime,
        "database_update_in_progress": app_state["update_in_progress"],
        "last_database_update": app_state["last_db_update"].isoformat() if app_state["last_db_update"] else None,
        "environment": Config.ENVIRONMENT
    }


@app.get("/stats", dependencies=[Depends(verify_api_key)])
async def get_stats():
    """Get database statistics"""
    return get_database_stats()


@app.get("/cve/{cve_id}", dependencies=[Depends(verify_api_key)])
async def lookup_cve(
    cve_id: str,
    include_cvss_details: bool = Query(False),
    include_risk_analysis: bool = Query(False),
    include_references: bool = Query(True)
):
    """Lookup a single CVE by ID"""
    try:
        cve_data = get_cve_info(cve_id, include_cwe_details=True, force_api=False)
        
        if not cve_data:
            raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")
        
        response_data = {
            "cve_id": cve_id,
            "found": True,
            "data": cve_data
        }
        
        if include_cvss_details:
            cvss_v3 = get_cvss_details(cve_id, 'v3')
            cvss_v2 = get_cvss_details(cve_id, 'v2')
            response_data["cvss_details"] = {"v3": cvss_v3, "v2": cvss_v2}
        
        if include_risk_analysis:
            risk_v3 = analyze_cvss_risk(cve_id, 'v3')
            risk_v2 = analyze_cvss_risk(cve_id, 'v2')
            response_data["risk_analysis"] = {"v3": risk_v3, "v2": risk_v2}
        
        # Limit references
        if not include_references and "references" in response_data["data"]:
            del response_data["data"]["references"]
        elif include_references and "references" in response_data["data"]:
            response_data["data"]["references"] = response_data["data"]["references"][:10]
        
        return response_data
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error looking up CVE {cve_id}: {str(e)}")


@app.post("/cve/batch", dependencies=[Depends(verify_api_key)])
async def batch_lookup_cve(request: CVERequest):
    """Batch lookup multiple CVEs"""
    start_time = time.time()
    results = []
    found_count = 0
    
    for cve_id in request.cve_ids[:50]:  # Limit to 50 CVEs
        try:
            cve_data = get_cve_info(cve_id, include_cwe_details=True, force_api=False)
            
            if cve_data:
                response_item = {
                    "cve_id": cve_id,
                    "found": True,
                    "data": cve_data
                }
                
                if request.include_cvss_details:
                    cvss_v3 = get_cvss_details(cve_id, 'v3')
                    cvss_v2 = get_cvss_details(cve_id, 'v2')
                    response_item["cvss_details"] = {"v3": cvss_v3, "v2": cvss_v2}
                
                if request.include_risk_analysis:
                    risk_v3 = analyze_cvss_risk(cve_id, 'v3')
                    risk_v2 = analyze_cvss_risk(cve_id, 'v2')
                    response_item["risk_analysis"] = {"v3": risk_v3, "v2": risk_v2}
                
                # Limit references
                if not request.include_references and "references" in response_item["data"]:
                    del response_item["data"]["references"]
                elif request.include_references and "references" in response_item["data"]:
                    response_item["data"]["references"] = response_item["data"]["references"][:10]
                
                found_count += 1
            else:
                response_item = {
                    "cve_id": cve_id,
                    "found": False,
                    "error": "CVE not found"
                }
            
            results.append(response_item)
            
        except Exception as e:
            results.append({
                "cve_id": cve_id,
                "found": False,
                "error": str(e)
            })
    
    processing_time = time.time() - start_time
    
    return {
        "results": results,
        "summary": {
            "total": len(request.cve_ids),
            "processed": len(results),
            "found": found_count,
            "not_found": len(results) - found_count
        },
        "processing_time": processing_time
    }


@app.get("/cwe/{cwe_id}", dependencies=[Depends(verify_api_key)])
async def lookup_cwe(cwe_id: Union[str, int]):
    """Lookup a single CWE by ID"""
    try:
        cwe_data = get_cwe_info(cwe_id)
        
        if not cwe_data:
            raise HTTPException(status_code=404, detail=f"CWE {cwe_id} not found")
        
        return {
            "cwe_id": str(cwe_id),
            "found": True,
            "data": cwe_data
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error looking up CWE {cwe_id}: {str(e)}")


@app.post("/cwe/batch", dependencies=[Depends(verify_api_key)])
async def batch_lookup_cwe(request: CWERequest):
    """Batch lookup multiple CWEs"""
    start_time = time.time()
    results = []
    found_count = 0
    
    for cwe_id in request.cwe_ids[:50]:  # Limit to 50 CWEs
        try:
            cwe_data = get_cwe_info(cwe_id)
            
            if cwe_data:
                results.append({
                    "cwe_id": str(cwe_id),
                    "found": True,
                    "data": cwe_data
                })
                found_count += 1
            else:
                results.append({
                    "cwe_id": str(cwe_id),
                    "found": False,
                    "error": "CWE not found"
                })
                
        except Exception as e:
            results.append({
                "cwe_id": str(cwe_id),
                "found": False,
                "error": str(e)
            })
    
    processing_time = time.time() - start_time
    
    return {
        "results": results,
        "summary": {
            "total": len(request.cwe_ids),
            "processed": len(results),
            "found": found_count,
            "not_found": len(results) - found_count
        },
        "processing_time": processing_time
    }


@app.post("/update", dependencies=[Depends(verify_api_key)])
async def trigger_database_update(background_tasks: BackgroundTasks):
    """Manually trigger database update"""
    if app_state["update_in_progress"]:
        return {
            "status": "already_in_progress",
            "message": "Database update is already in progress"
        }
    
    def update_db_background():
        try:
            app_state["update_in_progress"] = True
            print("📊 Starting manual database update...")
            update_cwe_database()
            # Quick update for cloud deployment
            current_year = datetime.now().year
            update_database(years=[current_year, current_year - 1], include_modified=True)
            app_state["last_db_update"] = datetime.now()
            print("✅ Manual database update completed")
        except Exception as e:
            print(f"❌ Manual database update failed: {e}")
        finally:
            app_state["update_in_progress"] = False
    
    background_tasks.add_task(update_db_background)
    
    return {
        "status": "started",
        "message": "Database update has been started in the background",
        "timestamp": datetime.now().isoformat()
    }


if __name__ == "__main__":
    if Config.API_KEY == "seevee-default-key-change-me":
        print("⚠️  WARNING: Using default API key. Please set SEEVEE_API_KEY environment variable.")
    
    uvicorn.run(
        "app:app",
        host=Config.HOST,
        port=Config.PORT,
        reload=Config.ENVIRONMENT == "development"
    ) 