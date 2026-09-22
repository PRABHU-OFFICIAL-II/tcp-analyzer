import { useState } from "react";
import { BrowserRouter, Routes, Route, Navigate, useNavigate } from "react-router-dom";
import UploadPage from "./pages/UploadPage.jsx";
import ReportPage from "./pages/ReportPage.jsx";
import ComparePage from "./pages/ComparePage.jsx";
import SettingsPage from "./pages/SettingsPage.jsx";
import HistoryPage from "./pages/HistoryPage.jsx";

function AppContent() {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  async function handleUpload(file) {
    setLoading(true);
    setError(null);
    const form = new FormData();
    form.append("file", file);
    try {
      const res = await fetch("/api/analyze", { method: "POST", body: form });
      if (!res.ok) { const e = await res.json(); throw new Error(e.detail || "Analysis failed"); }
      setReport(await res.json());
      navigate("/report");
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  function handleReset() {
    setReport(null);
    navigate("/");
  }

  function handleLoadFromHistory(r) {
    setReport(r);
    navigate("/report");
  }

  return (
    <Routes>
      <Route path="/" element={
        <UploadPage
          onUpload={handleUpload}
          loading={loading}
          error={error}
          onCompare={() => navigate("/compare")}
          onSettings={() => navigate("/settings")}
          onHistory={() => navigate("/history")}
        />
      } />
      <Route path="/report" element={
        report ? <ReportPage report={report} onReset={handleReset} /> : <Navigate to="/" replace />
      } />
      <Route path="/compare" element={<ComparePage onBack={() => navigate(-1)} />} />
      <Route path="/settings" element={<SettingsPage onBack={() => navigate(-1)} />} />
      <Route path="/history" element={<HistoryPage onLoad={handleLoadFromHistory} onBack={() => navigate(-1)} />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AppContent />
    </BrowserRouter>
  );
}
