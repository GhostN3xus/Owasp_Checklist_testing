const securityTools = [
  {
    name: "Burp Suite",
    category: "Proxy / DAST",
    description: "Interceptação, fuzzing, automação de ataques web e APIs."
  },
  {
    name: "OWASP ZAP",
    category: "Proxy / Scanner",
    description: "Scanner open-source com automação para pipelines CI/CD."
  },
  {
    name: "sqlmap",
    category: "Injeção SQL",
    description: "Automação para testes de SQLi, enumeração de bancos e dumping de dados."
  },
  {
    name: "Semgrep",
    category: "SAST",
    description: "Regas de análise estática para diversas linguagens com foco em OWASP e compliance."
  },
  {
    name: "Bandit",
    category: "SAST Python",
    description: "Detecta vulnerabilidades comuns em projetos Python."
  },
  {
    name: "gosec",
    category: "SAST Go",
    description: "Scanner estático para código Go com foco em vulnerabilidades críticas."
  },
  {
    name: "testssl.sh",
    category: "Hardening TLS",
    description: "Validação de configurações TLS, protocolos, cipher suites e certificados."
  },
  {
    name: "nmap",
    category: "Recon",
    description: "Varredura de portas, serviços e scripts NSE para detecção de vulnerabilidades."
  },
  {
    name: "MobSF",
    category: "Mobile",
    description: "Framework de análise estática/dinâmica para apps iOS/Android."
  },
  {
    name: "trivy",
    category: "Container / SCA",
    description: "Scanner de vulnerabilidades, IaC e secrets para containers, repositórios e sistemas."
  }
];

if (typeof globalThis !== "undefined") {
  globalThis.securityTools = securityTools;
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = securityTools;
}
