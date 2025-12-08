from app.models.productModel import ProductMaster
from app.schemas.productSchema import ProductCreateSchema
from app.extension import db


class ProductService:
    
    @staticmethod
    def product_exists(sku: str) -> bool:
        return db.session.query(ProductMaster).filter_by(sku=sku).first() 

    # create user
    @staticmethod
    def create_product(product_data: dict) -> ProductMaster:
        

        new_product = ProductMaster(
            product_name=product_data.product_name,
            sku=product_data.sku,
            product_category=product_data.product_category,
            product_attribute=product_data.product_attribute,
            product_sub_attribute=product_data.product_sub_attribute,
            product_descriptions=product_data.product_descriptions,
            brand=product_data.brand,
            price=product_data.price,
            moq=product_data.moq,
            cbm=product_data.cbm
        )
        db.session.add(new_product)
        db.session.commit()

        return new_product


    # get all products
    @staticmethod
    def get_all_products():
        return db.session.query(ProductMaster).all()


    @staticmethod
    def delete_product(sku):
        product = ProductService.product_exists(sku)
        if not product:
            return False
        db.session.delete(product)
        db.session.commit()
        return True
    

    @staticmethod
    def update_product_put(sku: str, update_data):
        product = ProductService.product_exists(sku)
        if not product:
            return None

        product.product_name = update_data.product_name
        product.sku = update_data.sku
        product.product_category = update_data.product_category
        product.product_attribute = update_data.product_attribute
        product.product_sub_attribute = update_data.product_sub_attribute
        product.product_descriptions = update_data.product_descriptions
        product.brand = update_data.brand
        product.price = update_data.price
        product.moq = update_data.moq
        product.cbm = update_data.cbm


        db.session.commit()
        return product
    

    @staticmethod
    def update_product_patch(sku: str, update_data):
        product = ProductService.product_exists(sku)
        if not product:
            return None

        for field, value in update_data.dict(exclude_unset=True).items():
            setattr(product, field, value)

        db.session.commit()
        return product