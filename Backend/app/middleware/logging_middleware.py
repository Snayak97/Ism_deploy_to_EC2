import time
from flask import request, g
from app.utils.logger_config import get_logger

logger = get_logger("request_logger")

def setup_logging_middleware(app):
    """
    Industrial-grade logging middleware for Flask.
    Logs every request, response, duration, and errors.
    """

    @app.before_request
    def start_timer():
        """
        Executed before each request.
        Stores start time and logs request details.
        """
        g.start_time = time.time()  # store start time for duration calculation

        # Log request details
        logger.info(
            f"➡ START Request | Method: {request.method} | Path: {request.path} | "
            f"Remote Addr: {request.remote_addr} | Body: {request.get_data(as_text=True)}"
        )

    @app.after_request
    def log_response(response):
        """
        Executed after each request.
        Logs response status, duration, and request info.
        """
        duration = round(time.time() - g.start_time, 4)

        logger.info(
            f"✅ END Request | Method: {request.method} | Path: {request.path} | "
            f"Status: {response.status_code} | Duration: {duration}s"
        )
        return response

    @app.teardown_request
    def log_exception(error=None):
        """
        Executed when a request ends, even if an exception occurs.
        Logs the exception if present.
        """
        if error:
            duration = round(time.time() - g.get('start_time', time.time()), 4)
            logger.error(
                f"❌ EXCEPTION | Method: {request.method} | Path: {request.path} | "
                f"Duration: {duration}s | Exception: {error}",
                exc_info=True
            )
