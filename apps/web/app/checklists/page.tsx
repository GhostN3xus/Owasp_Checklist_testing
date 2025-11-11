"use client";

import { useEffect, useState } from "react";
import Link from "next/link";

interface Checklist {
  id: string;
  slug: string;
  title: string;
  version: string;
  category: string;
  itemCount: number;
}

export default function ChecklistsPage() {
  const [checklists, setChecklists] = useState<Checklist[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchChecklists();
  }, []);

  const fetchChecklists = async () => {
    try {
      const res = await fetch("/api/v1/checklists");
      const data = await res.json();
      setChecklists(data.data || []);
    } catch (error) {
      console.error("Error fetching checklists:", error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) return <div style={{ padding: "20px" }}>Loading...</div>;

  return (
    <div style={{ padding: "20px" }}>
      <Link href="/dashboard">← Back to Dashboard</Link>

      <h1 style={{ marginTop: "20px" }}>Security Checklists</h1>

      {checklists.length === 0 ? (
        <p>No checklists available.</p>
      ) : (
        <div style={{ marginTop: "20px" }}>
          {checklists.map((checklist) => (
            <div
              key={checklist.id}
              style={{
                padding: "15px",
                marginBottom: "10px",
                backgroundColor: "#f3f4f6",
                borderRadius: "8px",
                borderLeft: "4px solid #2563eb",
              }}
            >
              <h3>{checklist.title}</h3>
              <p style={{ color: "#6b7280", fontSize: "14px" }}>
                Category: {checklist.category} | Items: {checklist.itemCount} |
                Version: {checklist.version}
              </p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
