import { PrismaClient } from "@prisma/client";
import { hash } from "bcryptjs";
import * as fs from "fs";
import * as path from "path";
import * as yaml from "js-yaml";

const prisma = new PrismaClient();

interface ChecklistItem {
  code: string;
  title: string;
  description: string;
  severity: string;
  cweId?: string;
  bodyMd?: string;
  references?: string;
  tools?: string;
  category: string;
  sort: number;
}

interface ChecklistYAML {
  id: string;
  title: string;
  version: string;
  category: string;
  items: ChecklistItem[];
}

async function seed() {
  console.log("🌱 Starting seed...");

  // Create default admin user
  const adminEmail = "admin@local";
  const hashedPassword = await hash("admin123!", 10);

  const admin = await prisma.user.upsert({
    where: { email: adminEmail },
    update: {},
    create: {
      email: adminEmail,
      password: hashedPassword,
      name: "Admin User",
      role: "ADMIN",
    },
  });

  console.log(`✅ Admin user: ${admin.email}`);

  // Load and import YAML checklists
  const checklistsDir = path.join(
    __dirname,
    "../../packages/content/checklists"
  );
  const yamlFiles = fs
    .readdirSync(checklistsDir)
    .filter((f) => f.endsWith(".yaml"));

  for (const file of yamlFiles) {
    const filePath = path.join(checklistsDir, file);
    const fileContent = fs.readFileSync(filePath, "utf-8");
    const data = yaml.load(fileContent) as ChecklistYAML;

    if (!data || !data.id) {
      console.warn(`⚠️ Skipping invalid YAML file: ${file}`);
      continue;
    }

    const checklist = await prisma.checklist.upsert({
      where: { slug: data.id },
      update: {
        title: data.title,
        version: data.version,
      },
      create: {
        slug: data.id,
        title: data.title,
        version: data.version,
        category: data.category,
      },
    });

    console.log(`✅ Checklist: ${checklist.title} (${data.id})`);

    // Upsert items
    if (data.items && Array.isArray(data.items)) {
      for (const item of data.items) {
        await prisma.checklistItem.upsert({
          where: {
            checklistId_code: {
              checklistId: checklist.id,
              code: item.code,
            },
          },
          update: {
            title: item.title,
            description: item.description,
            severity: item.severity,
            bodyMd: item.bodyMd,
          },
          create: {
            checklistId: checklist.id,
            code: item.code,
            title: item.title,
            description: item.description,
            severity: item.severity,
            cweId: item.cweId,
            bodyMd: item.bodyMd,
            references: item.references,
            tools: item.tools,
            category: item.category,
            sort: item.sort,
          },
        });
      }

      // Update item count
      const itemCount = await prisma.checklistItem.count({
        where: { checklistId: checklist.id },
      });

      await prisma.checklist.update({
        where: { id: checklist.id },
        data: { itemCount },
      });

      console.log(`   📋 ${itemCount} items imported`);
    }
  }

  console.log("✨ Seed completed successfully!");
}

seed()
  .catch((e) => {
    console.error("❌ Seed error:", e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
