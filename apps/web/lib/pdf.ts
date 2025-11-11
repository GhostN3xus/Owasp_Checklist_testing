import { chromium } from "playwright";
import * as fs from "fs";
import * as path from "path";

export async function generatePDF(
  htmlContent: string,
  assessmentId: string
): Promise<string> {
  const browser = await chromium.launch({
    args: ["--no-sandbox"],
  });

  try {
    const page = await browser.newPage();
    await page.setContent(htmlContent, { waitUntil: "networkidle" });

    const tmpDir = "/tmp";
    if (!fs.existsSync(tmpDir)) {
      fs.mkdirSync(tmpDir, { recursive: true });
    }

    const filePath = path.join(tmpDir, `assessment-${assessmentId}.pdf`);

    await page.pdf({
      path: filePath,
      format: "A4",
      margin: {
        top: "1cm",
        right: "1cm",
        bottom: "1cm",
        left: "1cm",
      },
    });

    return filePath;
  } finally {
    await browser.close();
  }
}
