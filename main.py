from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
import time
from hashlib import sha256
from typing import Optional

app = FastAPI(
    title="Password Generator API",
    description="Generate secure passwords using SHA256 hashing with timestamp",
    version="1.0.0"
)

class PasswordRequest(BaseModel):
    length: int
    phrase: Optional[str] = "The Tomb of Saint Nicholas"

class PasswordResponse(BaseModel):
    password: str
    timestamp: int
    length: int

@app.get("/")
async def root():
    return {"message": "Password Generator API", "endpoints": ["/generate", "/docs"], "author": "rohan srivastav"}

@app.get("/generate", response_model=PasswordResponse)
async def generate_password(
    length: int = Query(..., ge=1, le=64, description="Length of password (1-64 characters)"),
    phrase: str = Query("The Tomb of Saint Nicholas", description="Base phrase for password generation")
):
    """
    Generate a password using SHA256 hash of phrase + current timestamp
    
    - **length**: Length of the generated password (1-64 characters)
    - **phrase**: Base phrase to use for generation (optional)
    """
    try:
        epoch_time = int(time.time())
        input_string = phrase + str(epoch_time)
        hash_digest = sha256(input_string.encode('utf-8')).hexdigest()
        
        # Ensure we don't exceed hash length
        if length > len(hash_digest):
            raise HTTPException(
                status_code=400, 
                detail=f"Requested length ({length}) exceeds maximum hash length ({len(hash_digest)})"
            )
        
        password = hash_digest[0:length]
        
        return PasswordResponse(
            password=password,
            timestamp=epoch_time,
            length=length
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating password: {str(e)}")

@app.post("/generate", response_model=PasswordResponse)
async def generate_password_post(request: PasswordRequest):
    """
    Generate a password using POST request with JSON body
    
    - **length**: Length of the generated password (1-64 characters)
    - **phrase**: Base phrase to use for generation
    """
    if request.length < 1 or request.length > 64:
        raise HTTPException(
            status_code=400,
            detail="Length must be between 1 and 64 characters"
        )
    
    try:
        epoch_time = int(time.time())
        input_string = request.phrase + str(epoch_time)
        hash_digest = sha256(input_string.encode('utf-8')).hexdigest()
        
        if request.length > len(hash_digest):
            raise HTTPException(
                status_code=400,
                detail=f"Requested length ({request.length}) exceeds maximum hash length ({len(hash_digest)})"
            )
        
        password = hash_digest[0:request.length]
        
        return PasswordResponse(
            password=password,
            timestamp=epoch_time,
            length=request.length
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating password: {str(e)}")

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": int(time.time())}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
