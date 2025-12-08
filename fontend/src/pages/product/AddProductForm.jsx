import React, { useState } from "react";
import axios from "axios";

const AddProductForm = ({ onAddSuccess, onClose }) => {
  const [formData, setFormData] = useState({
    product_name: "",
    sku: "",
    product_category: "",
    product_attribute: "",
    product_sub_attribute: "",
    product_descriptions: "",
    brand: "",
    price: "",
    moq: "",
    cbm: "",
  });

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  // Block spaces anywhere in input
  const handleChange = (e) => {
    const { name, value } = e.target;
    // Reject if value contains spaces
    if (!value.includes(" ")) {
      setFormData((prev) => ({ ...prev, [name]: value }));
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError("");

    // Trim all string fields before sending
    const trimmedData = {};
    for (const key in formData) {
      trimmedData[key] =
        typeof formData[key] === "string"
          ? formData[key].trim()
          : formData[key];
    }

    try {
      await axios.post(
        "http://127.0.0.1:5000/api/v1/product/create_product",
        trimmedData
      );
      setLoading(false);
      onAddSuccess();
    } catch (err) {
      setError("Failed to add product. Please try again.");
      setLoading(false);
    }
  };
  return (
    <form onSubmit={handleSubmit} className="space-y-4 text-sm">
      <div className="flex flex-col  dark:bg-neutral-950 dark:text-white dark:from-gray-950 dark:via-gray-900 dark:to-gray-950">
        <label htmlFor="product_name" className="mb-1 font-semibold">
          Product Name
        </label>
        <input
          type="text"
          name="product_name"
          id="product_name"
          value={formData.product_name}
          onChange={handleChange}
          required
          maxLength={100}
          className="border border-gray-300 rounded px-2 py-1 focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
      </div>

      <div className="flex flex-col">
        <label htmlFor="sku" className="mb-1 font-semibold">
          SKU
        </label>
        <input
          type="text"
          name="sku"
          id="sku"
          value={formData.sku}
          onChange={handleChange}
          required
          maxLength={50}
          className="border border-gray-300 rounded px-2 py-1 focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="flex flex-col">
          <label htmlFor="product_category" className="mb-1 font-semibold">
            Category
          </label>
          <input
            type="text"
            name="product_category"
            id="product_category"
            value={formData.product_category}
            onChange={handleChange}
            maxLength={50}
            className="border border-gray-300 rounded px-2 py-1 focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <div className="flex flex-col">
          <label htmlFor="product_attribute" className="mb-1 font-semibold">
            Attribute
          </label>
          <input
            type="text"
            name="product_attribute"
            id="product_attribute"
            value={formData.product_attribute}
            onChange={handleChange}
            maxLength={50}
            className="border border-gray-300 rounded px-2 py-1 focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <div className="flex flex-col">
          <label htmlFor="product_sub_attribute" className="mb-1 font-semibold">
            Sub Attribute
          </label>
          <input
            type="text"
            name="product_sub_attribute"
            id="product_sub_attribute"
            value={formData.product_sub_attribute}
            onChange={handleChange}
            maxLength={50}
            className="border border-gray-300 rounded px-2 py-1 focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <div className="flex flex-col">
          <label htmlFor="brand" className="mb-1 font-semibold">
            Brand
          </label>
          <input
            type="text"
            name="brand"
            id="brand"
            value={formData.brand}
            onChange={handleChange}
            maxLength={50}
            className="border border-gray-300 rounded px-2 py-1 focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
      </div>

      <div className="flex flex-col">
        <label htmlFor="product_descriptions" className="mb-1 font-semibold">
          Description
        </label>
        <textarea
          name="product_descriptions"
          id="product_descriptions"
          value={formData.product_descriptions}
          onChange={handleChange}
          rows={2}
          maxLength={250}
          className="border border-gray-300 rounded px-2 py-1 focus:outline-none focus:ring-2 focus:ring-blue-500 resize-none"
        />
      </div>

      <div className="grid grid-cols-3 gap-4">
        <div className="flex flex-col">
          <label htmlFor="price" className="mb-1 font-semibold">
            Price
          </label>
          <input
            type="text"
            name="price"
            id="price"
            value={formData.price}
            onChange={handleChange}
            placeholder="e.g. 19.99"
            required
            className="border border-gray-300 rounded px-2 py-1 focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <div className="flex flex-col">
          <label htmlFor="moq" className="mb-1 font-semibold">
            MOQ
          </label>
          <input
            type="text"
            name="moq"
            id="moq"
            value={formData.moq}
            onChange={handleChange}
            placeholder="e.g. 100"
            required
            className="border border-gray-300 rounded px-2 py-1 focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <div className="flex flex-col">
          <label htmlFor="cbm" className="mb-1 font-semibold">
            CBM
          </label>
          <input
            type="text"
            name="cbm"
            id="cbm"
            value={formData.cbm}
            onChange={handleChange}
            placeholder="e.g. 0.45"
            required
            className="border border-gray-300 rounded px-2 py-1 focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
      </div>

      {error && <p className="text-red-600 text-sm">{error}</p>}

      <div className="flex justify-end space-x-4">
        <button
          type="button"
          onClick={onClose}
          className="px-4 py-2 rounded border border-gray-400 hover:bg-gray-100 transition"
        >
          Cancel
        </button>
        <button
          type="submit"
          disabled={loading}
          className="px-4 py-2 rounded bg-blue-600 text-white hover:bg-blue-700 transition disabled:opacity-50"
        >
          {loading ? "Saving..." : "Save"}
        </button>
      </div>
    </form>
  );
};

export default AddProductForm;
