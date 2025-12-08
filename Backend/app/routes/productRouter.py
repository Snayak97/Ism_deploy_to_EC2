from flask import Blueprint, request, jsonify
from app.schemas.productSchema import ProductCreateSchema,ProductResponseSchema,ProductUpdatePutSchema,ProductUpdatePatchSchema
from app.services.productServices import ProductService


product_bp = Blueprint("product", __name__, url_prefix="/api/v1/product")


@product_bp.route('/create_product', methods=['POST'])
def create_product():
    try:
    
        data = request.get_json()
        try:
            product_data = ProductCreateSchema(**data)
        except :
            return jsonify({"error":"validation_errors"}), 422

        if ProductService.product_exists(product_data.sku):
            return jsonify({"error": "Product already exists"}), 403  

        product = ProductService.create_product(product_data)

        product_response = ProductResponseSchema.from_orm(product)
        return jsonify({"message": "Product created successfully!","product":product_response.dict()}), 201

    except:
        return jsonify({"error": "Internal server error"}), 500


@product_bp.route('/get_products', methods=['GET'])
def get_products():
    try:
        products = ProductService.get_all_products()
        product_response = [ProductResponseSchema.from_orm(product).dict() for product in products]
        return jsonify({"products": product_response}), 200
    except:

        return jsonify({"error": "Internal server error"}), 500
    

@product_bp.route('/get_product/<string:sku>', methods=['GET'])
def get_product(sku):
    try:
        product = ProductService.product_exists(sku)
        print(product)
        if not product:
            return jsonify({"error": "Product not found"}), 404
        product_response = ProductResponseSchema.from_orm(product).dict()
        return jsonify({"products": product_response}), 200
    except:
        return jsonify({"error": "Internal server error"}), 500

@product_bp.route('/delete_product/<string:sku>', methods=['DELETE'])
def delete_product(sku):
    try:
        deleted = ProductService.delete_product(sku)
        if not deleted:
            return jsonify({"error": "Product not found"}), 404
        return jsonify({"message": "Product deleted successfully"}), 200

    except:
        return jsonify({"error": "Internal server error"}), 500
    


@product_bp.route('/update_product/<string:sku>', methods=['PUT'])
def update_product(sku):
    try:
        data = request.get_json()
        try:
            update_data = ProductUpdatePutSchema(**data)
        except :
            return jsonify({"error":"validation_errors"}), 422

        product = ProductService.update_product_put(sku, update_data)
        if not product:
            return jsonify({"error": "product not found"}), 404

        return jsonify({"message": "product fully updated", "product": ProductResponseSchema.from_orm(product).dict()}), 200
    except:
        return jsonify({"error": "Internal server error"}), 500
    

@product_bp.route('/update_product/<string:sku>', methods=['PATCH'])
def update_product_patch(sku):
    try:
        data = request.get_json()
        try:
            update_data = ProductUpdatePatchSchema(**data)
        except:
            return jsonify({"error":"validation_errors"}), 422

        product = ProductService.update_product_patch(sku, update_data)
        if not product:
            return jsonify({"error": "product not found"}), 404

        return jsonify({"message": "product partially updated", "product": ProductResponseSchema.from_orm(product).dict()}), 200
    except:
        return jsonify({"error": "Internal server error"}), 500
    