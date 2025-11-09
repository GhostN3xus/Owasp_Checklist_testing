import { NestFactory } from '@nestjs/core';
import { ValidationPipe, VersioningType } from '@nestjs/common';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { ConfigService } from '@nestjs/config';
import * as helmet from 'helmet';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    logger: ['error', 'warn', 'log', 'debug'],
  });

  const configService = app.get(ConfigService);
  const port = configService.get('PORT') || 4000;

  // Security - Helmet
  app.use(helmet());

  // CORS
  app.enableCors({
    origin: configService.get('NODE_ENV') === 'production'
      ? [configService.get('APP_URL')]
      : true,
    methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
    maxAge: 3600,
  });

  // API Versioning
  app.enableVersioning({
    type: VersioningType.URI,
    defaultVersion: '2',
    prefix: 'api/v',
  });

  // Global Validation Pipe
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      transformOptions: {
        enableImplicitConversion: true,
      },
    }),
  );

  // Swagger API Documentation
  if (configService.get('NODE_ENV') !== 'production') {
    const config = new DocumentBuilder()
      .setTitle('AppSec Dashboard API')
      .setDescription('OWASP Security Checklist & Pentesting Guide - API Documentation')
      .setVersion('2.0.0')
      .addBearerAuth()
      .addTag('auth', 'Authentication endpoints')
      .addTag('users', 'User management')
      .addTag('projects', 'Project management')
      .addTag('checklists', 'Checklist items')
      .addTag('evidence', 'Evidence upload and management')
      .addTag('exports', 'Report exports (PDF, Excel, JSON)')
      .addTag('analytics', 'Analytics and metrics')
      .build();

    const document = SwaggerModule.createDocument(app, config);
    SwaggerModule.setup('api/docs', app, document, {
      swaggerOptions: {
        persistAuthorization: true,
      },
    });
  }

  await app.listen(port);

  console.log(`
  ╔═══════════════════════════════════════════════════════════╗
  ║                                                           ║
  ║   🔒  AppSec Dashboard v2.0 API                          ║
  ║                                                           ║
  ║   Environment:  ${configService.get('NODE_ENV')?.padEnd(40)} ║
  ║   Port:         ${String(port).padEnd(40)} ║
  ║   URL:          http://localhost:${port}${' '.repeat(25)} ║
  ║   API Docs:     http://localhost:${port}/api/docs${' '.repeat(13)} ║
  ║                                                           ║
  ╚═══════════════════════════════════════════════════════════╝
  `);
}

bootstrap();
