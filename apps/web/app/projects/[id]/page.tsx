"use client";

import { useEffect, useState } from "react";
import Link from "next/link";

interface Project {
  id: string;
  name: string;
  description?: string;
  scope?: string;
  assessments: any[];
}

export default function ProjectPage({ params }: { params: { id: string } }) {
  const [project, setProject] = useState<Project | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchProject();
  }, [params.id]);

  const fetchProject = async () => {
    try {
      const res = await fetch(`/api/v1/projects/${params.id}`);
      const data = await res.json();
      setProject(data.data);
    } catch (error) {
      console.error("Error fetching project:", error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) return <div style={{ padding: "20px" }}>Loading...</div>;
  if (!project)
    return <div style={{ padding: "20px" }}>Project not found</div>;

  return (
    <div style={{ padding: "20px" }}>
      <Link href="/dashboard">← Back to Dashboard</Link>

      <h1 style={{ marginTop: "20px" }}>{project.name}</h1>
      {project.description && <p>{project.description}</p>}
      {project.scope && <p>Scope: {project.scope}</p>}

      <h2 style={{ marginTop: "30px" }}>Assessments</h2>
      {project.assessments.length === 0 ? (
        <p>No assessments for this project.</p>
      ) : (
        <div>
          {project.assessments.map((assessment: any) => (
            <div key={assessment.id} style={{ padding: "10px", marginBottom: "10px", backgroundColor: "#f3f4f6" }}>
              <Link href={`/assessments/${assessment.id}`}>
                {assessment.title} - {assessment.status}
              </Link>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
