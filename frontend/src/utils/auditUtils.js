export const SERVICES = ['ALL', 'S3', 'EC2', 'RDS', 'IAM', 'LAMBDA', 'APIGATEWAY', 'CLOUDFRONT'];

export const SEVERITIES = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'ADVISORY'];

export const normalizeResource = (item) => ({
  name: item.resource_name || item.resource_id || 'Unknown',
  service: (item.service || 'S3').toUpperCase(),
  region: item.region || 'global',
  severity: item.highest_severity_level || item.severity_level || 'CLEAN',
  score: item.final_risk_score !== undefined ? item.final_risk_score : (item.risk_score || 0),
  problems: item.individual_problems || []
});

export const exportToCSV = (findings) => {
  if (!findings || findings.length === 0) return;

  const headers = ["Resource Identifier", "Service", "Region", "Severity", "Risk Score", "Vulnerabilities Count"];
  const rows = findings.map(item => {
    const norm = normalizeResource(item);
    return [
      `"${norm.name}"`,
      `"${norm.service}"`,
      `"${norm.region}"`,
      `"${norm.severity}"`,
      norm.score.toFixed(2),
      norm.problems.length
    ];
  });

  const csvContent = "data:text/csv;charset=utf-8," + [headers.join(","), ...rows.map(e => e.join(","))].join("\n");
  const encodedUri = encodeURI(csvContent);
  const link = document.createElement("a");
  link.setAttribute("href", encodedUri);
  link.setAttribute("download", `aws_security_audit_${new Date().toISOString().slice(0, 10)}.csv`);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
};