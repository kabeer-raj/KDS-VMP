use async_trait::async_trait;
use chrono::Utc;

use crate::error::InfraError;
use crate::traits::PdfGenerator;
use shared_types::{ApplicationResponse, ScanResponse, VulnerabilityDetail};

pub struct SimplePdfGenerator;

impl SimplePdfGenerator {
    pub fn new() -> Self {
        Self
    }

    fn sanitize_pdf_text(text: &str) -> String {
        text.replace('\\', "\\\\")
            .replace('(', "\\(")
            .replace(')', "\\)")
            .chars()
            .filter(|c| c.is_ascii())
            .collect()
    }

    fn build_pdf_document(&self, title: &str, subtitle: &str, sections: &[(&str, Vec<String>)]) -> Vec<u8> {
        let mut stream_content = String::new();

        // Setup coordinate system and fonts
        stream_content.push_str("BT\n");
        stream_content.push_str("/F2 20 Tf\n"); // Bold title
        stream_content.push_str("50 740 Td\n");
        stream_content.push_str(&format!("({}) Tj\n", Self::sanitize_pdf_text(title)));

        stream_content.push_str("/F1 12 Tf\n"); // Regular subtitle
        stream_content.push_str("0 -24 Td\n");
        stream_content.push_str(&format!("({}) Tj\n", Self::sanitize_pdf_text(subtitle)));

        let mut current_y = 690;
        for (sec_title, lines) in sections {
            if current_y < 100 {
                break;
            }
            stream_content.push_str("0 -30 Td\n");
            stream_content.push_str("/F2 14 Tf\n"); // Bold section heading
            stream_content.push_str(&format!("({}) Tj\n", Self::sanitize_pdf_text(sec_title)));
            current_y -= 30;

            stream_content.push_str("/F1 10 Tf\n"); // Section content
            for line in lines {
                if current_y < 80 {
                    break;
                }
                stream_content.push_str("0 -16 Td\n");
                stream_content.push_str(&format!("({}) Tj\n", Self::sanitize_pdf_text(line)));
                current_y -= 16;
            }
        }

        stream_content.push_str("ET\n");

        let stream_bytes = stream_content.as_bytes();
        let stream_len = stream_bytes.len();

        let mut pdf = Vec::new();
        pdf.extend_from_slice(b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n");

        let mut offsets = Vec::new();

        // Object 1: Catalog
        offsets.push(pdf.len());
        pdf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");

        // Object 2: Pages
        offsets.push(pdf.len());
        pdf.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");

        // Object 3: Page
        offsets.push(pdf.len());
        pdf.extend_from_slice(
            b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R /F2 6 0 R >> >> >>\nendobj\n",
        );

        // Object 4: Stream
        offsets.push(pdf.len());
        let stream_obj_header = format!("4 0 obj\n<< /Length {} >>\nstream\n", stream_len);
        pdf.extend_from_slice(stream_obj_header.as_bytes());
        pdf.extend_from_slice(stream_bytes);
        pdf.extend_from_slice(b"\nendstream\nendobj\n");

        // Object 5: Standard Helvetica Font
        offsets.push(pdf.len());
        pdf.extend_from_slice(
            b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n",
        );

        // Object 6: Standard Helvetica-Bold Font
        offsets.push(pdf.len());
        pdf.extend_from_slice(
            b"6 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj\n",
        );

        // Cross-reference table
        let xref_offset = pdf.len();
        pdf.extend_from_slice(b"xref\n0 7\n0000000000 65535 f \n");
        for offset in offsets {
            let entry = format!("{:010} 00000 n \n", offset);
            pdf.extend_from_slice(entry.as_bytes());
        }

        // Trailer
        let trailer = format!(
            "trailer\n<< /Size 7 /Root 1 0 R >>\nstartxref\n{}\n%%EOF\n",
            xref_offset
        );
        pdf.extend_from_slice(trailer.as_bytes());

        pdf
    }
}

impl Default for SimplePdfGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PdfGenerator for SimplePdfGenerator {
    async fn generate_scan_report(
        &self,
        scan: &ScanResponse,
        app: &ApplicationResponse,
        findings: &[VulnerabilityDetail],
    ) -> Result<Vec<u8>, InfraError> {
        let title = format!("Executive Security Assessment: {}", app.name);
        let subtitle = format!(
            "Generated on: {} UTC | Target: {}",
            Utc::now().format("%Y-%m-%d %H:%M:%S"),
            app.base_url
        );

        let sec1_lines = vec![
            format!("Scan ID: {}", scan.id),
            format!("Scan Type: {:?}", scan.scan_type),
            format!("Status: {:?}", scan.status),
            format!("Environment: {:?}", app.environment),
            format!("Criticality: {:?}", app.criticality),
            format!("Overall Risk Score: {:.2} / 10.00", scan.overall_risk_score),
            format!("Duration: {} seconds", scan.duration_seconds.unwrap_or(0)),
        ];

        let sec2_lines = vec![
            format!("Total Findings: {}", scan.severity_counts.total()),
            format!("  Critical: {}", scan.severity_counts.critical),
            format!("  High: {}", scan.severity_counts.high),
            format!("  Medium: {}", scan.severity_counts.medium),
            format!("  Low: {}", scan.severity_counts.low),
            format!("  Informational: {}", scan.severity_counts.info),
            format!(
                "Diff vs Previous: +{} New, -{} Fixed, !{} Regressed",
                scan.diff_summary.new_count, scan.diff_summary.fixed_count, scan.diff_summary.regressed_count
            ),
        ];

        let mut sec3_lines = Vec::new();
        if findings.is_empty() {
            sec3_lines.push("No vulnerabilities reported for this assessment.".to_string());
        } else {
            for (idx, f) in findings.iter().take(10).enumerate() {
                sec3_lines.push(format!(
                    "{}. [{:?}] {} (CVSS {:.1})",
                    idx + 1,
                    f.summary.severity,
                    f.summary.title,
                    f.summary.cvss_score
                ));
                sec3_lines.push(format!(
                    "    OWASP: {} | Location: {} {}",
                    f.summary.owasp_category, f.summary.http_method, f.summary.normalized_path
                ));
            }
            if findings.len() > 10 {
                sec3_lines.push(format!("... and {} more findings.", findings.len() - 10));
            }
        }

        let sections = vec![
            ("1. Assessment Overview", sec1_lines),
            ("2. Severity & Diff Breakdown", sec2_lines),
            ("3. Top Findings & Vulnerabilities", sec3_lines),
        ];

        Ok(self.build_pdf_document(&title, &subtitle, &sections))
    }

    async fn generate_app_report(
        &self,
        app: &ApplicationResponse,
        scans: &[ScanResponse],
        open_vulns: &[VulnerabilityDetail],
    ) -> Result<Vec<u8>, InfraError> {
        let title = format!("Application Security Posture: {}", app.name);
        let subtitle = format!(
            "Generated on: {} UTC | Environment: {:?}",
            Utc::now().format("%Y-%m-%d %H:%M:%S"),
            app.environment
        );

        let sec1_lines = vec![
            format!("Application ID: {}", app.id),
            format!("Base URL: {}", app.base_url),
            format!("Team: {}", app.team_name.as_deref().unwrap_or("Unassigned")),
            format!("Criticality: {:?}", app.criticality),
            format!("Latest Risk Score: {:.2} / 10.00", app.latest_risk_score),
            format!("Last Scanned: {:?}", app.last_scanned_at),
        ];

        let sec2_lines = vec![
            format!("Total Recorded Scans: {}", scans.len()),
            format!("Current Open Findings: {}", open_vulns.len()),
        ];

        let sections = vec![
            ("1. Application Metadata", sec1_lines),
            ("2. Historical Overview", sec2_lines),
        ];

        Ok(self.build_pdf_document(&title, &subtitle, &sections))
    }
}
