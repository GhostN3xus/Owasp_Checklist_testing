/**
 * Mapeamento completo de referências para URLs de documentação
 * Usado para renderizar links clicáveis nas referências
 */

export const documentationLinks = {
  // OWASP Top 10 2021
  "OWASP Top 10": "https://owasp.org/www-project-top-ten/",
  "OWASP Top 10 – A01": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
  "OWASP Top 10 – A02": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
  "OWASP Top 10 – A03": "https://owasp.org/Top10/A03_2021-Injection/",
  "OWASP Top 10 – A04": "https://owasp.org/Top10/A04_2021-Insecure_Design/",
  "OWASP Top 10 – A05": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
  "OWASP Top 10 – A06": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
  "OWASP Top 10 – A07": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
  "OWASP Top 10 – A08": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
  "OWASP Top 10 – A09": "https://owasp.org/Top10/A09_2021-Logging_and_Monitoring_Failures/",
  "OWASP Top 10 – A10": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_(SSRF)/",
  "OWASP Top 10 for Large Language Model Applications": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",

  // OWASP Cheat Sheets
  "OWASP Authentication Cheat Sheet": "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
  "OWASP Cryptographic Storage Cheat Sheet": "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
  "OWASP Cheat Sheet – Session Management": "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
  "OWASP Cheat Sheet – Command Injection": "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html",
  "OWASP Cheat Sheet – Business Logic": "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_References_Prevention_Cheat_Sheet.html",
  "OWASP Secure Headers Project": "https://owasp.org/www-project-secure-headers/",
  "OWASP Deserialization Cheat Sheet": "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
  "OWASP Logging Cheat Sheet": "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html",
  "OWASP SSRF Prevention Cheat Sheet": "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
  "OWASP Cheat Sheet Series": "https://cheatsheetseries.owasp.org/",

  // OWASP Testing Guide
  "OWASP Testing Guide": "https://owasp.org/www-project-web-security-testing-guide/",
  "OWASP Testing Guide – Business Logic": "https://owasp.org/www-project-web-security-testing-guide/",

  // OWASP SAMM
  "OWASP SAMM": "https://owasp.org/www-project-samm/",
  "OWASP SAMM – Design": "https://owasp.org/www-project-samm/",

  // OWASP API Security
  "OWASP API Security Top 10": "https://owasp.org/www-project-api-security/",

  // NIST Standards
  "NIST 800-63-3 – Digital Identity Guidelines": "https://pages.nist.gov/800-63-3/",
  "NIST 800-63B": "https://pages.nist.gov/800-63-3/sp800-63b.html",
  "NIST SP 800-57": "https://csrc.nist.gov/publications/detail/sp/800-57/part-1/final",
  "NIST 800-92": "https://csrc.nist.gov/publications/detail/sp/800-92/final",
  "NIST 800-190": "https://csrc.nist.gov/publications/detail/sp/800-190/final",

  // CWE References
  "CWE-613 – Insufficient Session Expiration": "https://cwe.mitre.org/data/definitions/613.html",
  "CWE-502": "https://cwe.mitre.org/data/definitions/502.html",
  "CWE-89 – SQL Injection": "https://cwe.mitre.org/data/definitions/89.html",

  // Mozilla
  "Mozilla SSL Configuration Guide": "https://wiki.mozilla.org/Security/Server_Side_TLS",

  // CIS Benchmarks
  "CIS Benchmarks": "https://www.cisecurity.org/cis-benchmarks/",
  "CIS Docker Benchmark": "https://www.cisecurity.org/benchmark/docker",
  "CIS Controls IG2 – 6": "https://www.cisecurity.org/controls/",

  // PTES
  "PTES – Vulnerability Analysis": "https://www.penetrationtestingestandardsexecution.org/",
  "PTES – External Network Discovery": "https://www.penetrationtestingestandardsexecution.org/",

  // SLSA Framework
  "SLSA Framework": "https://slsa.dev/",

  // MITRE
  "MITRE D3FEND": "https://d3fend.mitre.org/",

  // AWS
  "AWS SSRF Mitigations": "https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter-introduction.html",
  "AWS Security Best Practices": "https://aws.amazon.com/architecture/security-identity-compliance/",

  // Azure
  "Azure Security Best Practices": "https://docs.microsoft.com/en-us/azure/security/",

  // GCP
  "Google Cloud Security": "https://cloud.google.com/security/",

  // Microsoft
  "Microsoft Threat Modeling Tool Guide": "https://learn.microsoft.com/en-us/windows/security/threat-protection/",

  // OWASP Dependency Check
  "OWASP Dependency-Check": "https://owasp.org/www-project-dependency-check/",

  // Testing Tools
  "Burp Suite": "https://portswigger.net/burp",
  "OWASP ZAP": "https://www.zaproxy.org/",

  // Vulnerability Databases
  "NVD – National Vulnerability Database": "https://nvd.nist.gov/",
  "CVE Details": "https://www.cvedetails.com/",

  // Code Review Tools
  "SonarQube": "https://www.sonarqube.org/",
  "Checkmarx": "https://checkmarx.com/",

  // Container Security
  "Docker Security": "https://docs.docker.com/engine/security/",
  "Kubernetes Security": "https://kubernetes.io/docs/concepts/security/",

  // Additional OWASP Resources
  "OWASP API Security": "https://owasp.org/www-project-api-security/",
  "OWASP Benchmark": "https://owasp.org/www-project-benchmark/",
  "OWASP DevSecOps Guideline": "https://owasp.org/www-project-devsecops-guideline/",
  "OWASP MASVS": "https://owasp.org/www-project-mobile-app-security/",
  "OWASP MSTG": "https://owasp.org/www-project-mobile-security-testing-guide/",
  "OWASP ModSecurity CRS": "https://owasp.org/www-project-modsecurity-core-rule-set/",
  "OWASP Security Champions Playbook": "https://owasp.org/www-project-security-champions-playbook/",
  "OWASP Server Security": "https://owasp.org/www-community/Server_Side_Request_Forgery",
  "OWASP Testing Guide – XSS": "https://owasp.org/www-project-web-security-testing-guide/",
  "OWASP Top 10: A06-Vulnerable and Outdated Components": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
  "OWASP Top 10 – Broken Authentication": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
  "OWASP LLM Top 10": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
  "OWASP Cheat Sheet: Access Control": "https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html",
  "OWASP Cheat Sheet: Authentication": "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
  "OWASP Cheat Sheet: Content Security Policy": "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
  "OWASP Cheat Sheet: Cryptographic Storage": "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
  "OWASP Cheat Sheet: Injection Prevention": "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html",
  "OWASP Cheat Sheet: Input Validation": "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html",
  "OWASP Cheat Sheet: Logging": "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html",
  "OWASP Cheat Sheet: Password Storage": "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
  "OWASP Cheat Sheet: Threat Modeling": "https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html",
  "OWASP Cheat Sheet: XSS Prevention": "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
  "OWASP SAMM – Implementation": "https://owasp.org/www-project-samm/",
  "OWASP Secure Headers": "https://owasp.org/www-project-secure-headers/",

  // AWS
  "AWS S3 Security Best Practices": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/security.html",
  "CIS AWS Foundations Benchmark": "https://www.cisecurity.org/benchmark/amazon_web_services",

  // Azure
  "Azure network security best practices": "https://docs.microsoft.com/en-us/azure/security/fundamentals/network-best-practices",
  "Azure security best practices and patterns": "https://docs.microsoft.com/en-us/azure/security/fundamentals/best-practices-and-patterns",
  "Handle a potential security incident in Azure": "https://docs.microsoft.com/en-us/azure/security/fundamentals/security-incident-response",
  "Managing service account keys": "https://cloud.google.com/docs/authentication/managing-service-accounts",
  "VPC network security best practices": "https://cloud.google.com/docs/vpc/best-practices",
  "Google Cloud security best practices checklist": "https://cloud.google.com/docs/foundations/best-practices/checklist",
  "Responding to compromised AWS credentials": "https://aws.amazon.com/pt/premiumsupport/knowledge-center/compromised-credentials-aws/",

  // CIS Benchmarks Extended
  "CIS IIS Benchmark": "https://www.cisecurity.org/benchmark/microsoft_iis_web_server",
  "CIS Linux Benchmark": "https://www.cisecurity.org/benchmark/centos_linux",
  "CIS Linux Firewall": "https://www.cisecurity.org/benchmark/ubuntu_linux",
  "CIS Windows Server Benchmark": "https://www.cisecurity.org/benchmark/microsoft_windows_server_2022",
  "CIS Windows Logging": "https://www.cisecurity.org/benchmark/microsoft_windows_10_enterprise",
  "CIS Apache Benchmark": "https://www.cisecurity.org/benchmark/apache_http_server",

  // Server Configuration Guides
  "Apache Security Guide": "https://httpd.apache.org/docs/2.4/security/",
  "Microsoft IIS Security Hardening": "https://docs.microsoft.com/en-us/iis/get-started/whats-new-in-iis-10",
  "Microsoft TLS Best Practices": "https://docs.microsoft.com/en-us/windows-server/security/tls/tls-best-practices",
  "Microsoft Secure DevOps": "https://aka.ms/securedevops",
  "Microsoft Security Baselines": "https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-security-baselines",
  "Microsoft Advanced Audit Policy": "https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings",
  "Nginx Rate Limiting Guide": "https://nginx.org/en/docs/http/ngx_http_limit_req_module.html",

  // Programming Language Security
  "Go Security Guide": "https://golang.org/doc/effective_go#security",
  "Python Security Guide": "https://python.readthedocs.io/en/latest/library/security_warnings.html",

  // Security Tools & Standards
  "Lynis Documentation": "https://cisofy.com/lynis/",
  "Mozilla Observatory": "https://observatory.mozilla.org/",
  "PortSwigger SSRF Cheatsheet": "https://portswigger.net/burp/cheat-sheet",
  "OSI (Open Source Initiative)": "https://opensource.org/",
  "NTIA: The Minimum Elements For a Software Bill of Materials": "https://ntia.gov/SBOM",
  "PTES – Pre-engagement": "https://www.penetrationtestingestandardsexecution.org/",
  "PTES – Intelligence Gathering": "https://www.penetrationtestingestandardsexecution.org/",

  // CWE References
  "CWE-918": "https://cwe.mitre.org/data/definitions/918.html",

  // External Security Resources
  "https://semgrep.dev/p/owasp-top-ten": "https://semgrep.dev/p/owasp-top-ten",
  "https://www.pentest-standard.org/index.php/Pre-engagement": "https://www.pentest-standard.org/index.php/Pre-engagement",
};

/**
 * Função para converter referência em URL
 * @param {string} reference - O texto da referência
 * @returns {string|null} A URL correspondente ou null se não encontrada
 */
export function getReferenceUrl(reference) {
  return documentationLinks[reference] || null;
}

/**
 * Função para verificar se uma referência tem URL correspondente
 * @param {string} reference - O texto da referência
 * @returns {boolean} true se a referência tem URL
 */
export function hasDocumentationLink(reference) {
  return documentationLinks.hasOwnProperty(reference);
}

/**
 * Função para renderizar uma referência como link HTML
 * @param {string} reference - O texto da referência
 * @returns {string} HTML da referência com link ou texto simples
 */
export function renderReferenceLink(reference) {
  const url = getReferenceUrl(reference);
  if (url) {
    return `<a href="${url}" target="_blank" class="reference-link" title="Abrir documentação">
      <span class="reference-text">${escapeHtml(reference)}</span>
      <span class="external-icon">↗</span>
    </a>`;
  }
  return `<span class="reference-text">${escapeHtml(reference)}</span>`;
}

/**
 * Função auxiliar para escapar HTML
 * @param {string} text - O texto a ser escapado
 * @returns {string} Texto escapado
 */
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}
