
import time
from flask import g, request, current_app
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity

def metrics_middleware():
    """
    Middleware to track:
    - Active requests (Gauge)
    - Request latency (Histogram)
    """
    # Skip preflight requests
    if request.method == "OPTIONS":
        return None

    try:
        # Track active requests
        current_app.active_users.inc()
        g.start_time = time.time()

        try:
            verify_jwt_in_request(optional=True)
            user_id = get_jwt_identity()
            if user_id and user_id not in current_app.logged_in_users_set:
                current_app.logged_in_users_set.add(user_id)
                current_app.logged_in_users.inc()
        except Exception:
            pass  # Ignore JWT errors in metrics

    except Exception as e:
        current_app.logger.error(f"Metrics middleware error: {e}")


def after_request_metrics(response):
    try:
        latency = time.time() - getattr(g, "start_time", time.time())
        current_app.request_latency.labels(endpoint=request.path).observe(latency)
        current_app.active_users.dec()

        # Track HTTP errors
        if response.status_code >= 400:
            current_app.http_errors_total.labels(
                status_code=str(response.status_code),
                endpoint=request.path
            ).inc()
    except Exception as e:
        current_app.logger.error(f"After-request metrics error: {e}")
    return response

