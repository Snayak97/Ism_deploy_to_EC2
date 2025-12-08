from flask import Flask,jsonify,current_app
from sqlalchemy import text
from .config import Config
from flask_migrate import Migrate
from .extension import db,jwt,mail
from flask_cors import CORS
from app.database.redis_client import token_in_blocklist
from .registerRouter import register_all_routes

from prometheus_flask_exporter import PrometheusMetrics
from prometheus_client import Counter, Gauge, Histogram
from .middleware.metrics_middleware import after_request_metrics, metrics_middleware

from app.utils.logger_config import LoggerConfig
from app.middleware.logging_middleware import setup_logging_middleware





def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    mail.init_app(app)
    jwt.init_app(app)
    migrate = Migrate(app, db)

    CORS(app, resources={r"/api/*": {"origins": Config.FRONTEND_URL}}, supports_credentials=True)
    # CORS(app, origins=["http://192.168.1.49:5173"], supports_credentials=True)

    # Setup industrial-level logging
    LoggerConfig.setup(app, log_level='DEBUG', json_logs=False)


    with app.app_context():
        try:
            db.create_all()
            db.session.execute(text('SELECT 1'))
            print("Database connected successfully!")
        except Exception as e:
            print(f"Database connection failed: {e}")



    @jwt.token_in_blocklist_loader
    def check_if_token_revoked(jwt_header, jwt_payload):
        try:
            return token_in_blocklist(jwt_payload["jti"])
        except Exception as e:
            print(f"Redis check failed: {e}")
            return True
    
        
    # Register all routes
    register_all_routes(app)
    
    

    # --------------------------------------------------
    # PROMETHEUS - INDUSTRIAL LEVEL METRICS
    # --------------------------------------------------
    # metrics = PrometheusMetrics(app, default_labels={"app": "inventory_flask_app"})
    # metrics = PrometheusMetrics(app, defaults_prefix='flask', path='/metrics', default_labels={"app": "inventory_flask_app"})

    metrics = PrometheusMetrics(app, path='/metrics', default_labels={"app": "inventory_flask_app"}, group_by='endpoint')


    # Counters
    app.login_success = Counter(
        'user_login_success_total',
        'Total successful logins'
      
    )
    app.login_failed = Counter(
        'user_login_failed_total',
        'Total failed login attempts'
        
    )
    app.logout_total = Counter(
        'user_logout_total',
        'Total user logouts'
    )
        

    # Gauges
    app.active_users = Gauge(
        'active_users_total',
        'Number of active users currently accessing the API'
    )
    app.logged_in_users = Gauge(
        'logged_in_users_total',
        'Number of currently logged-in users with valid JWT'
    )
    app.request_latency = Histogram('flask_request_latency_seconds', 'Request latency in seconds', ['endpoint'])

    app.http_errors_total = Counter(
    'http_errors_total',
    'Total HTTP errors by status code and endpoint',
    ['status_code', 'endpoint'])

    app.logged_in_users_set = set()
    app.before_request(metrics_middleware)
    app.after_request(after_request_metrics)

    

    

    @app.route('/')
    def home():
        return jsonify({"message": "Welcome to Flask API!"})
    
    setup_logging_middleware(app)
    app.logger.info("🚀 Flask app started with industrial-grade middleware logging")
    return app
