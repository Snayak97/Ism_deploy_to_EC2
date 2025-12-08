import React, { useRef, useState, useEffect } from "react";
import { FiUpload } from "react-icons/fi";
import axios from "axios";
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Typography,
  List,
  ListItem,
  ListItemText,
} from "@mui/material";
import AllDataTables from "./AllDataTables";
import MasterAllData from "../Masteralldata/MasterAllData";

const UploadMasterData = () => {
  const fileInputRef = useRef(null);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");
  const [responseData, setResponseData] = useState(null);
  const [openModal, setOpenModal] = useState(false);
  const [errorSummary, setErrorSummary] = useState(null);
  const [errorFileUrl, setErrorFileUrl] = useState(null);

  const handleIconClick = () => fileInputRef.current?.click();

  const handleFileChange = async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const formData = new FormData();
    formData.append("file", file);

    try {
      setLoading(true);
      setMessage("");
      setResponseData(null);
      setErrorSummary(null);
      setErrorFileUrl(null);

      const res = await axios.post(
        "http://127.0.0.1:5000/api/v1/marketplacemaster/upload_master_data",
        formData,
        { headers: { "Content-Type": "multipart/form-data" } }
      );

      const data = res.data;
      setResponseData(data);

      const hasErrors =
        data.processing_errors &&
        Object.keys(data.processing_errors).length > 0;

      if (!hasErrors) {
        setMessage("✅ All data uploaded successfully.");
      } else {
        setMessage(
          "⚠️ Upload completed with some errors. You can download the detailed error file for more information."
        );
        setErrorSummary(data.processing_errors);
        if (data.error_file_url) {
          setErrorFileUrl(data.error_file_url);
        }
        setOpenModal(true);
      }
    } catch (err) {
      console.error(err);
      setMessage("❌ Upload failed");
    } finally {
      setLoading(false);
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  };

  useEffect(() => {
    if (message) {
      const timer = setTimeout(() => setMessage(""), 30000);
      return () => clearTimeout(timer);
    }
  }, [message]);

  useEffect(() => {
    if (openModal) {
      const timer = setTimeout(() => setOpenModal(false), 30000);
      return () => clearTimeout(timer);
    }
  }, [openModal]);

  const handleCloseModal = () => setOpenModal(false);

  const handleDownloadErrorFile = () => {
    if (!errorFileUrl) return;
    const baseUrl = "http://127.0.0.1:5000";
    window.open(baseUrl + errorFileUrl, "_blank");
  };

  const renderErrorSummary = () => {
    if (!errorSummary) return null;
    return (
      <>
        <Typography variant="subtitle1" gutterBottom>
          Upload Errors Summary:
        </Typography>
        {Object.entries(errorSummary).map(([section, errors]) => (
          <div key={section} style={{ marginBottom: 16 }}>
            <Typography variant="subtitle2" color="primary" gutterBottom>
              {section.replace(/_/g, " ").toUpperCase()}
            </Typography>
            <List dense>
              {errors.map((err, idx) => (
                <ListItem key={idx} alignItems="flex-start">
                  <ListItemText
                    primary={`Row: ${err.row}`}
                    secondary={err.column_errors.map((colErr, i) => (
                      <Typography
                        component="span"
                        variant="body2"
                        color="error"
                        key={i}
                        display="block"
                      >
                        {colErr.column}: {colErr.message}
                      </Typography>
                    ))}
                  />
                </ListItem>
              ))}
            </List>
          </div>
        ))}
      </>
    );
  };

  return (
    <div className="container mx-auto p-4 max-w-7xl">
      {/* Upload Button */}
      <div className="flex justify-end p-4">
        <button
          onClick={handleIconClick}
          className="flex items-center gap-2 bg-green-600 text-white px-5 py-2 rounded-lg shadow hover:bg-green-700 cursor-pointer transition duration-200"
          disabled={loading}
        >
          <FiUpload className="text-xl" />
          {loading ? "Uploading..." : "Upload Master Tables"}
        </button>
        <input
          type="file"
          ref={fileInputRef}
          style={{ display: "none" }}
          onChange={handleFileChange}
          accept=".xlsx,.csv"
        />
      </div>

      {/* Upload Response Message */}
      {message && (
        <div
          className={`w-full mb-6 text-center px-4 py-3 rounded-lg transition duration-300 shadow text-sm font-medium ${
            message.startsWith("✅")
              ? "bg-green-100 text-green-800 border border-green-300"
              : message.startsWith("⚠️")
              ? "bg-yellow-100 text-yellow-800 border border-yellow-400"
              : "bg-red-100 text-red-800 border border-red-300"
          }`}
        >
          {message}
        </div>
      )}

      {/* Show Uploaded Valid Data or Fallback */}
      {responseData?.processing_results ? (
        <div className="overflow-auto">
          <h2 className="text-xl font-semibold text-green-700 mb-4 text-center">
            Below is your uploaded valid data
          </h2>
          <AllDataTables data={responseData.processing_results} />
        </div>
      ) : (
        <MasterAllData />
      )}

      {/* Error Modal */}
      <Dialog
        open={openModal}
        onClose={handleCloseModal}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>Upload completed with errors</DialogTitle>
        <DialogContent dividers>
          {renderErrorSummary()}
          {errorFileUrl && (
            <Typography variant="body2" sx={{ mt: 2 }}>
              You can download the detailed error file for more information.
            </Typography>
          )}
        </DialogContent>
        <DialogActions>
          {errorFileUrl && (
            <Button
              onClick={handleDownloadErrorFile}
              color="primary"
              variant="contained"
            >
              Download Error File
            </Button>
          )}
          <Button onClick={handleCloseModal} color="secondary">
            Close
          </Button>
        </DialogActions>
      </Dialog>
    </div>
  );
};

export default UploadMasterData;
