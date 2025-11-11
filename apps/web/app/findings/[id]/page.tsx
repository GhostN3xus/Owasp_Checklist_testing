"use client";

import { useEffect, useState } from "react";
import Link from "next/link";

interface Finding {
  id: string;
  title: string;
  description: string;
  severity: string;
  status: string;
  evidence: any[];
}

export default function FindingPage({ params }: { params: { id: string } }) {
  const [finding, setFinding] = useState<Finding | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchFinding();
  }, [params.id]);

  const fetchFinding = async () => {
    try {
      const res = await fetch(`/api/v1/findings/${params.id}`);
      const data = await res.json();
      setFinding(data.data);
    } catch (error) {
      console.error("Error fetching finding:", error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) return <div style={{ padding: "20px" }}>Loading...</div>;
  if (!finding)
    return <div style={{ padding: "20px" }}>Finding not found</div>;

  return (
    <div style={{ padding: "20px" }}>
      <Link href="/dashboard">← Back to Dashboard</Link>

      <h1 style={{ marginTop: "20px" }}>{finding.title}</h1>
      <div style={{ marginBottom: "20px" }}>
        <p>
          <strong>Severity:</strong>{" "}
          <span style={{ color: finding.severity === "CRITICAL" ? "red" : "orange" }}>
            {finding.severity}
          </span>
        </p>
        <p>
          <strong>Status:</strong> {finding.status}
        </p>
      </div>

      <h2>Description</h2>
      <p>{finding.description}</p>

      {finding.evidence && finding.evidence.length > 0 && (
        <>
          <h2 style={{ marginTop: "30px" }}>Evidence</h2>
          {finding.evidence.map((ev: any) => (
            <div key={ev.id} style={{ padding: "10px", backgroundColor: "#f3f4f6" }}>
              {ev.fileName}
            </div>
          ))}
        </>
      )}
    </div>
  );
}
