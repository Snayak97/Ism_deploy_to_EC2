from .routes.userRouter import user_bp
from .routes.productRouter import product_bp
from .routes.authRouter import auth_bp
from .routes.clientRouter import client_bp
from .routes.clientUserRouter import client_user_bp
from .routes.marketplaceMasterRouter import marketplacemaster_bp
from .routes.platformMasterRouter import platformmaster_bp
from .routes.shippinglocationMasterRouter import shippinglocationmaster_bp
from .routes.sellingPlatformMasterRouter import sellingplatformmaster_bp
from .routes.permissionRouter import permission_bp
from .middleware.active_user_middleware import active_user_check
from .middleware.metrics_middleware import metrics_middleware
from flask import current_app





def protect_blueprint(bp):
    @bp.before_request
    def protect():
        try:
            res = active_user_check()
            if res:
                return res
            metrics_middleware()
            return None
        except Exception as e:
            current_app.logger.error(f"Protect blueprint error: {e}")
    return bp




def register_all_routes(app):
    # Auth routes stay unprotected for login/signup
    app.register_blueprint(auth_bp)

    # Protect all other routes
    app.register_blueprint(user_bp)
    app.register_blueprint(product_bp)
    app.register_blueprint(protect_blueprint(client_bp))
    app.register_blueprint(protect_blueprint(client_user_bp))
    app.register_blueprint(marketplacemaster_bp)
    app.register_blueprint(platformmaster_bp)
    app.register_blueprint(shippinglocationmaster_bp)
    app.register_blueprint(sellingplatformmaster_bp)
    app.register_blueprint(protect_blueprint(permission_bp))

# def register_all_routes(app):
#     app.register_blueprint(user_bp)
#     app.register_blueprint(product_bp)
#     app.register_blueprint(auth_bp)
#     app.register_blueprint(client_bp)
#     app.register_blueprint(client_user_bp)
#     app.register_blueprint(marketplacemaster_bp)
#     app.register_blueprint(platformmaster_bp)
#     app.register_blueprint(shippinglocationmaster_bp)
#     app.register_blueprint(sellingplatformmaster_bp)
#     app.register_blueprint(permission_bp)
