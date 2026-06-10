import { useState } from "react";
import UploadPage from "./pages/UploadPage.jsx";
import ReportPage from "./pages/ReportPage.jsx";
import HistoryPage from "./pages/HistoryPage.jsx";
import ComparePage from "./pages/ComparePage.jsx";
import SettingsPage from "./pages/SettingsPage.jsx";

export default function App() {
  const [view, setView] = useState("upload");
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  async function handleUpload(file) {
    setLoading(true);
    setError(null);
    const form = new FormData();
    form.append("file", file);
    try {
      const res = await fetch("/api/analyze", { method: "POST", body: form });
      if (!res.ok) { const e = await res.json(); throw new Error(e.detail || "Analysis failed"); }
      setReport(await res.json());
      setView("report");
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  function handleReport(data) {
    setReport(data);
    setView("report");
  }

  if (view === "report" && report) {
    return <ReportPage report={report} onReset={() => { setReport(null); setView("upload"); }} />;
  }
  if (view === "history") {
    return <HistoryPage onLoad={handleReport} onBack={() => setView("upload")} />;
  }
  if (view === "compare") {
    return <ComparePage onBack={() => setView("upload")} />;
  }
  if (view === "settings") {
    return <SettingsPage onBack={() => setView("upload")} />;
  }
  return (
    <UploadPage
      onUpload={handleUpload}
      loading={loading}
      error={error}
      onHistory={() => setView("history")}
      onCompare={() => setView("compare")}
      onSettings={() => setView("settings")}
    />
  );
}
