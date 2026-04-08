import time

import structlog
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

logger = structlog.get_logger("api.access")

class StructlogMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        structlog.contextvars.clear_contextvars()
        
        # Add basic request info to context
        # e.g. structural log fields injected to all logs in current request
        client_ip = request.client.host if request.client else "unknown"
        structlog.contextvars.bind_contextvars(
            method=request.method,
            path=request.url.path,
            ip=client_ip
        )
        
        start_time = time.perf_counter()
        
        try:
            response = await call_next(request)
            
            process_time = time.perf_counter() - start_time
            logger.info("request_completed", 
                        status_code=response.status_code, 
                        process_time_ms=round(process_time * 1000, 2))
            
            return response
            
        except Exception as e:
            process_time = time.perf_counter() - start_time
            logger.exception("request_failed", 
                             process_time_ms=round(process_time * 1000, 2),
                             exc_info=e)
            raise
