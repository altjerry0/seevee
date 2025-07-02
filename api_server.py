#!/usr/bin/env python3
"""
SeeVee API Server - FastAPI service for CVE and CWE vulnerability lookups
"""

import os
import time
from datetime import datetime
from typing import List, Optional, Dict, Any, Union
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import uvicorn

from seevee import (
    get_cve_info, get_cwe_info, get_cvss_score, get_cvss_vector, 
    get_cvss_details, analyze_cvss_risk, update_database, update_cwe_database,
    CVEDatabase, format_duration
)


# Pydantic models for API requests/responses
class CVERequest(BaseModel):
    cve_ids: List[str] = Field(..., description="List of CVE IDs to lookup", example=["CVE-2021-44228", "CVE-2022-22965"])
    include_cvss_details: bool = Field(False, description="Include detailed CVSS vector components")
    include_risk_analysis: bool = Field(False, description="Include automated risk factor analysis")
    include_references: bool = Field(True, description="Include reference URLs (limited to first 10)")

class CWERequest(BaseModel):
    cwe_ids: List[Union[str, int]] = Field(..., description="List of CWE IDs to lookup", example=["CWE-79", 502, "CWE-89"])

class CVEResponse(BaseModel):
    cve_id: str
    found: bool
    data: Optional[Dict[str, Any]] = None
    cvss_details: Optional[Dict[str, Any]] = None
    risk_analysis: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

class CWEResponse(BaseModel):
    cwe_id: str
    found: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

class BatchCVEResponse(BaseModel):
    results: List[CVEResponse]
    summary: Dict[str, Any]
    processing_time: float

class BatchCWEResponse(BaseModel):
    results: List[CWEResponse]  
    summary: Dict[str, Any]
    processing_time: float

class DatabaseStats(BaseModel):
    cve_count: int
    cwe_count: int
    database_size_mb: float
    last_updated: Optional[str]

class UpdateResponse(BaseModel):
    success: bool
    message: str
    duration: Optional[str] = None
    vulnerabilities_imported: Optional[int] = None


# Global state
app_state = {
    "startup_time": None,
    "last_db_update": None,
    "update_in_progress": False
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager - handles startup and shutdown"""
    # Startup
    app_state["startup_time"] = datetime.now()
    
    # Check if we should update database on startup
    update_on_startup = os.getenv("UPDATE_DB_ON_STARTUP", "true").lower() == "true"
    skip_years = os.getenv("SKIP_YEARS", "").split(",") if os.getenv("SKIP_YEARS") else None
    
    if update_on_startup and not app_state["update_in_progress"]:
        print("🚀 Starting SeeVee API Server...")
        print("📊 Updating vulnerability database on startup...")
        
        try:
            app_state["update_in_progress"] = True
            start_time = time.time()
            
            # Update CWE database first (quick)
            print("📚 Updating CWE database...")
            cwe_success = update_cwe_database()
            
            # Update CVE database (can be slow)
            print("🔄 Updating CVE database...")
            if skip_years:
                print(f"⚡ Quick update mode - skipping years: {skip_years}")
                current_year = datetime.now().year
                years = [current_year, current_year - 1]  # Just recent years
                update_database(years=years, include_modified=True)
            else:
                # Full update (can take a while)
                update_database()
            
            duration = time.time() - start_time
            app_state["last_db_update"] = datetime.now()
            print(f"✅ Database update completed in {format_duration(duration)}")
            
        except Exception as e:
            print(f"❌ Database update failed: {e}")
        finally:
            app_state["update_in_progress"] = False
    else:
        print("🚀 Starting SeeVee API Server (skipping database update)...")
    
    yield
    
    # Shutdown
    print("👋 Shutting down SeeVee API Server...")


# Initialize FastAPI app
app = FastAPI(
    title="SeeVee API",
    description="CVE and CWE Vulnerability Information API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_database_stats() -> DatabaseStats:
    """Get database statistics"""
    try:
        db = CVEDatabase()
        
        # Get CVE count
        cve_count = 0
        import sqlite3
        with sqlite3.connect(db.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM cve_data")
            result = cursor.fetchone()
            cve_count = result[0] if result else 0
        
        # Get CWE count  
        cwe_count = db.get_cwe_count()
        
        # Get database file size
        db_size = 0
        if os.path.exists(db.db_path):
            db_size = os.path.getsize(db.db_path) / (1024 * 1024)  # MB
        
        return DatabaseStats(
            cve_count=cve_count,
            cwe_count=cwe_count,
            database_size_mb=round(db_size, 2),
            last_updated=app_state["last_db_update"].isoformat() if app_state["last_db_update"] else None
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get database stats: {str(e)}")


# API Routes

@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "service": "SeeVee API", 
        "version": "1.0.0",
        "description": "CVE and CWE Vulnerability Information API",
        "startup_time": app_state["startup_time"].isoformat() if app_state["startup_time"] else None,
        "endpoints": {
            "cve_lookup": "/cve/{cve_id}",
            "cve_batch": "/cve/batch",
            "cwe_lookup": "/cwe/{cwe_id}",
            "cwe_batch": "/cwe/batch",
            "health": "/health",
            "stats": "/stats",
            "docs": "/docs"
        }
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "uptime": str(datetime.now() - app_state["startup_time"]) if app_state["startup_time"] else None,
        "database_update_in_progress": app_state["update_in_progress"]
    }


@app.get("/stats")
async def get_stats():
    """Get database statistics"""
    return get_database_stats()


@app.get("/cve/{cve_id}")
async def lookup_cve(
    cve_id: str,
    include_cvss_details: bool = Query(False, description="Include detailed CVSS vector components"),
    include_risk_analysis: bool = Query(False, description="Include automated risk factor analysis"),
    include_references: bool = Query(True, description="Include reference URLs")
):
    """Lookup a single CVE"""
    try:
        start_time = time.time()
        
        # Get basic CVE info
        cve_data = get_cve_info(cve_id.upper())
        
        if not cve_data:
            return CVEResponse(
                cve_id=cve_id.upper(),
                found=False,
                error="CVE not found"
            )
        
        # Limit references if requested
        if include_references and cve_data.get('references'):
            cve_data['references'] = cve_data['references'][:10]
        elif not include_references:
            cve_data.pop('references', None)
        
        response = CVEResponse(
            cve_id=cve_id.upper(),
            found=True,
            data=cve_data
        )
        
        # Add CVSS details if requested
        if include_cvss_details:
            cvss_v3_details = get_cvss_details(cve_id, version='v3')
            cvss_v2_details = get_cvss_details(cve_id, version='v2')
            response.cvss_details = {
                'v3': cvss_v3_details,
                'v2': cvss_v2_details
            }
        
        # Add risk analysis if requested
        if include_risk_analysis:
            risk_v3 = analyze_cvss_risk(cve_id, version='v3')
            risk_v2 = analyze_cvss_risk(cve_id, version='v2')
            response.risk_analysis = {
                'v3': risk_v3,
                'v2': risk_v2
            }
        
        return response
        
    except Exception as e:
        return CVEResponse(
            cve_id=cve_id.upper(),
            found=False,
            error=str(e)
        )


@app.post("/cve/batch")
async def batch_lookup_cve(request: CVERequest):
    """Batch lookup multiple CVEs"""
    start_time = time.time()
    results = []
    found_count = 0
    
    for cve_id in request.cve_ids:
        try:
            # Get basic CVE info
            cve_data = get_cve_info(cve_id.upper())
            
            if not cve_data:
                results.append(CVEResponse(
                    cve_id=cve_id.upper(),
                    found=False,
                    error="CVE not found"
                ))
                continue
            
            found_count += 1
            
            # Limit references
            if request.include_references and cve_data.get('references'):
                cve_data['references'] = cve_data['references'][:10]
            elif not request.include_references:
                cve_data.pop('references', None)
            
            response = CVEResponse(
                cve_id=cve_id.upper(),
                found=True,
                data=cve_data
            )
            
            # Add CVSS details if requested
            if request.include_cvss_details:
                cvss_v3_details = get_cvss_details(cve_id, version='v3')
                cvss_v2_details = get_cvss_details(cve_id, version='v2')
                response.cvss_details = {
                    'v3': cvss_v3_details,
                    'v2': cvss_v2_details
                }
            
            # Add risk analysis if requested
            if request.include_risk_analysis:
                risk_v3 = analyze_cvss_risk(cve_id, version='v3')
                risk_v2 = analyze_cvss_risk(cve_id, version='v2')
                response.risk_analysis = {
                    'v3': risk_v3,
                    'v2': risk_v2
                }
            
            results.append(response)
            
        except Exception as e:
            results.append(CVEResponse(
                cve_id=cve_id.upper(),
                found=False,
                error=str(e)
            ))
    
    processing_time = time.time() - start_time
    
    return BatchCVEResponse(
        results=results,
        summary={
            "total_requested": len(request.cve_ids),
            "found": found_count,
            "not_found": len(request.cve_ids) - found_count,
            "success_rate": f"{(found_count / len(request.cve_ids) * 100):.1f}%"
        },
        processing_time=round(processing_time, 3)
    )


@app.get("/cwe/{cwe_id}")
async def lookup_cwe(cwe_id: Union[str, int]):
    """Lookup a single CWE"""
    try:
        cwe_data = get_cwe_info(cwe_id)
        
        if not cwe_data:
            return CWEResponse(
                cwe_id=str(cwe_id),
                found=False,
                error="CWE not found"
            )
        
        return CWEResponse(
            cwe_id=cwe_data['cwe_id'],
            found=True,
            data=cwe_data
        )
        
    except Exception as e:
        return CWEResponse(
            cwe_id=str(cwe_id),
            found=False,
            error=str(e)
        )


@app.post("/cwe/batch")
async def batch_lookup_cwe(request: CWERequest):
    """Batch lookup multiple CWEs"""
    start_time = time.time()
    results = []
    found_count = 0
    
    for cwe_id in request.cwe_ids:
        try:
            cwe_data = get_cwe_info(cwe_id)
            
            if not cwe_data:
                results.append(CWEResponse(
                    cwe_id=str(cwe_id),
                    found=False,
                    error="CWE not found"
                ))
                continue
            
            found_count += 1
            results.append(CWEResponse(
                cwe_id=cwe_data['cwe_id'],
                found=True,
                data=cwe_data
            ))
            
        except Exception as e:
            results.append(CWEResponse(
                cwe_id=str(cwe_id),
                found=False,
                error=str(e)
            ))
    
    processing_time = time.time() - start_time
    
    return BatchCWEResponse(
        results=results,
        summary={
            "total_requested": len(request.cwe_ids),
            "found": found_count,
            "not_found": len(request.cwe_ids) - found_count,
            "success_rate": f"{(found_count / len(request.cwe_ids) * 100):.1f}%"
        },
        processing_time=round(processing_time, 3)
    )


@app.post("/update")
async def trigger_update(
    background_tasks: BackgroundTasks,
    years: Optional[List[int]] = Query(None, description="Specific years to update"),
    include_modified: bool = Query(True, description="Include modified/recent feeds"),
    update_cwe: bool = Query(True, description="Update CWE database")
):
    """Trigger database update (runs in background)"""
    if app_state["update_in_progress"]:
        raise HTTPException(status_code=409, detail="Database update already in progress")
    
    def run_update():
        try:
            app_state["update_in_progress"] = True
            start_time = time.time()
            
            if update_cwe:
                print("📚 Updating CWE database...")
                update_cwe_database()
            
            print("🔄 Updating CVE database...")
            update_database(years=years, include_modified=include_modified)
            
            duration = time.time() - start_time
            app_state["last_db_update"] = datetime.now()
            print(f"✅ Database update completed in {format_duration(duration)}")
            
        except Exception as e:
            print(f"❌ Database update failed: {e}")
        finally:
            app_state["update_in_progress"] = False
    
    background_tasks.add_task(run_update)
    
    return UpdateResponse(
        success=True,
        message="Database update started in background. Check /health for progress."
    )


if __name__ == "__main__":
    # Configuration from environment variables
    host = os.getenv("API_HOST", "0.0.0.0")
    port = int(os.getenv("API_PORT", "8000"))
    workers = int(os.getenv("API_WORKERS", "1"))
    
    print(f"🚀 Starting SeeVee API Server on {host}:{port}")
    uvicorn.run(
        "api_server:app",
        host=host,
        port=port,
        workers=workers,
        reload=False
    ) 