"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";

interface Stats {
  projects: number;
  assessments: number;
  findings: number;
  checklists: number;
}

export default function Dashboard() {
  const router = useRouter();
  const [stats, setStats] = useState<Stats>({
    projects: 0,
    assessments: 0,
    findings: 0,
    checklists: 0,
  });
  const [loading, setLoading] = useState(true);
  const [user, setUser] = useState<any>(null);

  useEffect(() => {
    const userData = localStorage.getItem("user");
    if (!userData) {
      router.push("/sign-in");
      return;
    }
    setUser(JSON.parse(userData));

    fetchStats();
  }, [router]);

  const fetchStats = async () => {
    try {
      const [projectsRes, assessmentsRes, findingsRes, checklistsRes] =
        await Promise.all([
          fetch("/api/v1/projects"),
          fetch("/api/v1/assessments"),
          fetch("/api/v1/findings"),
          fetch("/api/v1/checklists"),
        ]);

      const projectsData = await projectsRes.json();
      const assessmentsData = await assessmentsRes.json();
      const findingsData = await findingsRes.json();
      const checklistsData = await checklistsRes.json();

      setStats({
        projects: projectsData.data?.length || 0,
        assessments: assessmentsData.data?.length || 0,
        findings: findingsData.data?.length || 0,
        checklists: checklistsData.data?.length || 0,
      });
    } catch (error) {
      console.error("Error fetching stats:", error);
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem("user");
    router.push("/sign-in");
  };

  if (loading) return <div style={{ padding: "20px" }}>Loading...</div>;

  return (
    <div style={{ padding: "20px" }}>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: "30px",
        }}
      >
        <h1>Dashboard</h1>
        <div>
          <span style={{ marginRight: "20px" }}>Welcome, {user?.name}</span>
          <button
            onClick={handleLogout}
            style={{
              padding: "8px 16px",
              backgroundColor: "#dc2626",
              color: "white",
              border: "none",
              cursor: "pointer",
            }}
          >
            Logout
          </button>
        </div>
      </div>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
          gap: "20px",
          marginBottom: "40px",
        }}
      >
        <StatCard label="Projects" value={stats.projects} />
        <StatCard label="Assessments" value={stats.assessments} />
        <StatCard label="Findings" value={stats.findings} />
        <StatCard label="Checklists" value={stats.checklists} />
      </div>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(250px, 1fr))",
          gap: "20px",
        }}
      >
        <ActionCard
          title="Projects"
          description="Manage security assessment projects"
          href="/projects"
          color="#3b82f6"
        />
        <ActionCard
          title="Checklists"
          description="Browse OWASP checklists"
          href="/checklists"
          color="#10b981"
        />
        <ActionCard
          title="Assessments"
          description="View and manage assessments"
          href="/assessments"
          color="#f59e0b"
        />
        <ActionCard
          title="Findings"
          description="Track security findings"
          href="/findings"
          color="#ef4444"
        />
      </div>
    </div>
  );
}

function StatCard({ label, value }: { label: string; value: number }) {
  return (
    <div
      style={{
        padding: "20px",
        backgroundColor: "#f3f4f6",
        borderRadius: "8px",
        textAlign: "center",
      }}
    >
      <p style={{ color: "#6b7280", marginBottom: "10px" }}>{label}</p>
      <p style={{ fontSize: "32px", fontWeight: "bold", color: "#1f2937" }}>
        {value}
      </p>
    </div>
  );
}

function ActionCard({
  title,
  description,
  href,
  color,
}: {
  title: string;
  description: string;
  href: string;
  color: string;
}) {
  return (
    <Link href={href}>
      <div
        style={{
          padding: "20px",
          backgroundColor: "white",
          border: `2px solid ${color}`,
          borderRadius: "8px",
          cursor: "pointer",
          transition: "transform 0.2s",
        }}
        onMouseEnter={(e) => {
          (e.currentTarget as HTMLElement).style.transform = "translateY(-4px)";
        }}
        onMouseLeave={(e) => {
          (e.currentTarget as HTMLElement).style.transform = "translateY(0)";
        }}
      >
        <h3 style={{ color: color, marginBottom: "8px" }}>{title}</h3>
        <p style={{ color: "#6b7280" }}>{description}</p>
      </div>
    </Link>
  );
}
