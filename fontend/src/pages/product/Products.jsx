// src/components/Products.jsx
import React, { useEffect, useState } from "react";
import axios from "axios";
import AddProductForm from "./AddProductForm";

const columns = [
  ["product_name", "Name"],
  ["sku", "SKU"],
  ["product_category", "Category"],
  ["product_attribute", "Attribute"],
  ["product_sub_attribute", "Sub Attribute"],
  ["product_descriptions", "Description"],
  ["brand", "Brand"],
  ["price", "Price"],
  ["moq", "MOQ"],
  ["cbm", "CBM"],
];

const ProductPage = () => {
  const [products, setProducts] = useState([]);
  const [showForm, setShowForm] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  const productsPerPage = 5;

  // For inline editing
  const [editSku, setEditSku] = useState(null);
  const [editFormData, setEditFormData] = useState({});

  useEffect(() => {
    fetchProducts();
  }, []);

  const fetchProducts = async () => {
    try {
      const res = await axios.get(
        "http://127.0.0.1:5000/api/v1/product/get_products"
      );
      setProducts(res.data.products || []);
    } catch (error) {
      console.error("Error fetching products:", error);
    }
  };

  // DELETE handler
  const handleDelete = async (sku) => {
    if (
      !window.confirm(
        `Are you sure you want to delete product with SKU: ${sku}?`
      )
    )
      return;
    try {
      await axios.delete(
        `http://127.0.0.1:5000/api/v1/product/delete_product/${sku}`
      );
      alert("Product deleted successfully");
      fetchProducts();
    } catch (error) {
      console.error("Delete failed:", error);
      alert("Failed to delete product");
    }
  };

  // Start editing
  const handleUpdateClick = (product) => {
    setEditSku(product.sku);
    setEditFormData({ ...product }); // clone product data to edit
  };

  // Cancel editing
  const handleCancelClick = () => {
    setEditSku(null);
    setEditFormData({});
  };

  // Handle input change in editable row
  const handleInputChange = (e, key) => {
    setEditFormData({
      ...editFormData,
      [key]: e.target.value,
    });
  };

  // Save updated product
  const handleSaveClick = async () => {
    try {
      await axios.put(
        `http://127.0.0.1:5000/api/v1/product/update_product/${editSku}`,
        editFormData
      );
      alert("Product updated successfully");
      setEditSku(null);
      setEditFormData({});
      fetchProducts();
    } catch (error) {
      console.error("Update failed:", error);
      alert("Failed to update product");
    }
  };

  // Pagination calculation
  const indexOfLast = currentPage * productsPerPage;
  const indexOfFirst = indexOfLast - productsPerPage;
  const currentProducts = products.slice(indexOfFirst, indexOfLast);
  const totalPages = Math.ceil(products.length / productsPerPage);

    return (
    <div className="p-4 max-w-6xl mx-auto  dark:bg-neutral-950 dark:text-white dark:from-gray-950 dark:via-gray-900 dark:to-gray-950 ">
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-xl font-bold">Product List</h2>
        <button
          className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
          onClick={() => setShowForm(true)}
        >
          Add Product
        </button>
      </div>

      {showForm && (
        <div className="fixed top-0 left-0 w-full h-full bg-gray-200 bg-opacity-50 flex justify-center items-center z-50   dark:bg-neutral-950 dark:text-white dark:from-gray-950 dark:via-gray-900 dark:to-gray-950">
          <div className="bg-white rounded-lg shadow-lg p-6 w-full max-w-3xl relative  dark:bg-neutral-950 dark:text-white dark:from-gray-950 dark:via-gray-900 dark:to-gray-950">
            <button
              className="absolute top-2 right-2 text-gray-600 hover:text-gray-900 dark:text-white dark:hover:text-gray-300 text-xl font-bold"
              onClick={() => setShowForm(false)}
              aria-label="Close form"
            >
              &times;
            </button>
            <AddProductForm
              onAddSuccess={() => {
                fetchProducts();
                setShowForm(false);
              }}
              onClose={() => setShowForm(false)}
            />
          </div>
        </div>
      )}

      <div className="overflow-x-auto ">
        <table className="w-full border border-gray-300 text-sm ">
          <thead className="bg-gray-100  dark:bg-neutral-950 dark:text-white dark:from-gray-950 dark:via-gray-900 dark:to-gray-950 ">
            <tr>
              {columns.map(([_, label]) => (
                <th key={label} className="px-4 py-2 border">{label}</th>
              ))}
              <th className="px-4 py-2 border">Actions</th>
            </tr>
          </thead>
          <tbody>
            {currentProducts.length > 0 ? (
              currentProducts.map((product) => (
                <tr key={product.sku} className="hover:bg-gray-50  dark:hover:bg-gray-700 dark:hover:text-yellow-300">
                  {columns.map(([key]) => (
                    <td key={key} className="px-4 py-2 border">
                      {editSku === product.sku ? (
                        <input
                          type="text"
                          value={editFormData[key] || ''}
                          onChange={(e) => handleInputChange(e, key)}
                          className="border rounded px-2 py-1 w-full text-sm"
                        />
                      ) : (
                        product[key] ?? '-'
                      )}
                    </td>
                  ))}
                  <td className="px-4 py-2 border">
                    {editSku === product.sku ? (
                      <div className="flex space-x-2">
                        <button
                          onClick={handleSaveClick}
                          className="px-3 py-1 bg-green-600 text-white rounded hover:bg-green-700 transition"
                        >
                          Save
                        </button>
                        <button
                          onClick={handleCancelClick}
                          className="px-3 py-1 bg-gray-400 text-white rounded hover:bg-gray-500 transition"
                        >
                          Cancel
                        </button>
                      </div>
                    ) : (
                      <div className="flex space-x-2">
                        <button
                          onClick={() => handleUpdateClick(product)}
                          className="px-3 py-1 bg-yellow-400 text-white rounded hover:bg-yellow-500 transition"
                        >
                          Update
                        </button>
                        <button
                          onClick={() => handleDelete(product.sku)}
                          className="px-3 py-1 bg-red-600 text-white rounded hover:bg-red-700 transition"
                        >
                          Delete
                        </button>
                      </div>
                    )}
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={columns.length + 1} className="text-center py-4">
                  No products available.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="flex justify-between mt-4">
        <button
          onClick={() => setCurrentPage(p => Math.max(p - 1, 1))}
          className="px-4 py-2 border rounded disabled:opacity-50"
          disabled={currentPage === 1}
        >
          Prev
        </button>
        <span className="self-center">
          Page {currentPage} of {totalPages}
        </span>
        <button
          onClick={() => setCurrentPage(p => Math.min(p + 1, totalPages))}
          className="px-4 py-2 border rounded disabled:opacity-50"
          disabled={currentPage === totalPages}
        >
          Next
        </button>
      </div>
    </div>
  );
};

export default ProductPage;
