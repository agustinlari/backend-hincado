import 'dotenv/config'
import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { Pool, PoolClient } from 'pg'
import { serve } from '@hono/node-server'
import { jwt, sign, verify } from 'hono/jwt'
import * as jose from 'jose'
import puppeteer from 'puppeteer'
import ExcelJS from 'exceljs'
import { PDFDocument } from 'pdf-lib'
import * as fs from 'fs'
import * as path from 'path'
import { AsyncLocalStorage } from 'async_hooks'

// AsyncLocalStorage para pasar el esquema de forma transparente a través del request
const schemaStorage = new AsyncLocalStorage<string>()

// Import routers
import { createAuthRouter } from './routes/auth'
import { createMesasRouter } from './routes/mesas'
import { createEnsayosRouter } from './routes/ensayos'
import { createInspeccionesRouter } from './routes/inspecciones'
import { createDashboardRouter } from './routes/dashboard'
import { createExportsRouter } from './routes/exports'

// Import middleware
import { createAuthMiddleware, createExportAuthMiddleware } from './middleware/auth'

// Import utilities
import { evaluateRule, getCellBackgroundColor, formatTestResult, generateReportHTML, getPDFStyles } from './utils/reportHelpers'

const app = new Hono()

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production'

// Configure CORS
app.use('/*', cors({
  origin: ['http://localhost:5173', 'http://localhost:3000', 'http://localhost:8789', 'https://aplicaciones.osmos.es:4444'],
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowHeaders: ['Content-Type', 'Authorization', 'X-Instalacion'],
}))

// Database connection
const pool = new Pool({
  user: process.env.DB_USER || 'postgres',
  host: process.env.DB_HOST || 'localhost',
  database: process.env.DB_NAME || 'fvinspeccioneshincas',
  password: process.env.DB_PASSWORD || 'Osmos2017',
  port: parseInt(process.env.DB_PORT || '5432'),
})

// Wrapper para pool.query que automáticamente establece el search_path correcto
const originalPoolQuery = pool.query.bind(pool)

// Override pool.query para usar el esquema del AsyncLocalStorage
pool.query = async function(textOrConfig: any, values?: any): Promise<any> {
  const esquema = schemaStorage.getStore()

  // Log para debugging (solo la primera vez por request)
  const queryPreview = typeof textOrConfig === 'string'
    ? textOrConfig.substring(0, 50).replace(/\s+/g, ' ')
    : 'config object'
  console.log(`📊 Query con esquema: ${esquema || 'public'} - ${queryPreview}...`)

  if (esquema) {
    // Si hay un esquema en el contexto, usar una conexión dedicada con ese esquema
    const client = await pool.connect()
    try {
      await client.query(`SET search_path TO ${esquema}, public`)
      if (typeof textOrConfig === 'string') {
        return await client.query(textOrConfig, values)
      } else {
        return await client.query(textOrConfig)
      }
    } finally {
      client.release()
    }
  } else {
    // Si no hay esquema (ej: endpoint de instalaciones), usar query normal con public
    const client = await pool.connect()
    try {
      await client.query('SET search_path TO public')
      if (typeof textOrConfig === 'string') {
        return await client.query(textOrConfig, values)
      } else {
        return await client.query(textOrConfig)
      }
    } finally {
      client.release()
    }
  }
} as typeof pool.query

// Cache de instalaciones válidas (se actualiza cada 5 minutos)
let instalacionesCache: { slug: string; esquema: string }[] = []
let instalacionesCacheTime = 0
const CACHE_DURATION = 5 * 60 * 1000 // 5 minutos

async function getInstalacionesValidas() {
  const now = Date.now()
  if (now - instalacionesCacheTime > CACHE_DURATION) {
    const result = await pool.query(
      'SELECT slug, esquema FROM public.instalaciones WHERE activo = true'
    )
    instalacionesCache = result.rows
    instalacionesCacheTime = now
    console.log('🔄 Cache de instalaciones actualizado:', instalacionesCache.map(i => i.slug))
  }
  return instalacionesCache
}

// Helper para obtener el esquema actual (para debugging)
function getCurrentSchema(): string | undefined {
  return schemaStorage.getStore()
}

// Endpoint público para listar instalaciones (sin auth)
app.get('/api/instalaciones', async (c) => {
  try {
    const result = await pool.query(`
      SELECT id, nombre, slug, descripcion, ubicacion, imagen_url, activo, created_at
      FROM public.instalaciones
      WHERE activo = true
      ORDER BY nombre
    `)
    return c.json(result.rows)
  } catch (error) {
    console.error('Error fetching instalaciones:', error)
    return c.json({ error: 'Failed to fetch instalaciones' }, 500)
  }
})

// Middleware para validar y configurar el esquema de instalación
app.use('/api/*', async (c, next) => {
  // Excluir rutas que no necesitan esquema
  const path = c.req.path
  if (path === '/api/instalaciones' ||
      path.startsWith('/api/auth/') ||
      path === '/api/auth') {
    return next()
  }

  const instalacionSlug = c.req.header('X-Instalacion')

  if (!instalacionSlug) {
    return c.json({ error: 'Header X-Instalacion es requerido' }, 400)
  }

  // Validar que la instalación existe
  const instalaciones = await getInstalacionesValidas()
  const instalacion = instalaciones.find(i => i.slug === instalacionSlug)

  if (!instalacion) {
    return c.json({ error: 'Instalación no válida' }, 400)
  }

  // Guardar el esquema en el contexto para uso posterior
  c.set('esquema', instalacion.esquema)
  c.set('instalacionSlug', instalacionSlug)

  // Ejecutar el resto del request dentro del AsyncLocalStorage con el esquema correcto
  return schemaStorage.run(instalacion.esquema, () => next())
})

// Create middleware instances
const authMiddleware = createAuthMiddleware()
const exportAuthMiddleware = createExportAuthMiddleware()

// Create and mount routers
const authRouter = createAuthRouter(JWT_SECRET)
const mesasRouter = createMesasRouter(pool, authMiddleware)
const ensayosRouter = createEnsayosRouter(pool, authMiddleware)
const inspeccionesRouter = createInspeccionesRouter(pool, authMiddleware)
const dashboardRouter = createDashboardRouter(pool, authMiddleware)
const exportsRouter = createExportsRouter(pool, exportAuthMiddleware)

// Mount all routers
app.route('/', authRouter)
app.route('/', mesasRouter)
app.route('/', ensayosRouter)
app.route('/', inspeccionesRouter)
app.route('/', dashboardRouter)
app.route('/', exportsRouter)

app.get('/', (c) => c.text('¡Hola desde Hono backend!'))

// Job management system for async report generation
interface ReportJob {
  id: string;
  status: 'pending' | 'processing' | 'completed' | 'error';
  data: any;
  result?: Buffer;
  error?: string;
  createdAt: Date;
  completedAt?: Date;
}

const reportJobs = new Map<string, ReportJob>();

// Clean up completed jobs after 30 minutes
setInterval(() => {
  const thirtyMinutesAgo = new Date(Date.now() - 30 * 60 * 1000);
  for (const [jobId, job] of reportJobs) {
    if (job.completedAt && job.completedAt < thirtyMinutesAgo) {
      reportJobs.delete(jobId);
      console.log(`🧹 Cleaned up completed job: ${jobId}`);
    }
  }
}, 5 * 60 * 1000); // Run cleanup every 5 minutes

function generateJobId(): string {
  return `job_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

// Extract the report generation logic into a reusable function
async function generateExcelTemplateReport(ids_mesas: number[]): Promise<Buffer> {
  console.log(`📋 Generating Excel template report for mesas: ${ids_mesas.join(', ')}`)
  
  // 1. Get template names for each mesa
  const mesasQuery = `
    SELECT m.id_mesa, m.nombre_mesa, ct.nombre_ct, mp.nombre_plantilla
    FROM mesas m
    JOIN mesa_plantillas mp ON m.id_plantilla = mp.id_plantilla
    JOIN cts ct ON m.id_ct = ct.id_ct
    WHERE m.id_mesa = ANY($1)
  `
  const mesasResult = await pool.query(mesasQuery, [ids_mesas])
  const mesaTemplates = mesasResult.rows
  
  console.log(`📋 Found templates:`, mesaTemplates)
  console.log(`📋 Templates count: ${mesaTemplates.length}`)
  
  // 2. Get latest test results for selected mesas
  const resultsQuery = `
    SELECT DISTINCT ON (id_mesa, id_componente_plantilla_1, id_tipo_ensayo)
      id_mesa,
      id_componente_plantilla_1,
      id_tipo_ensayo,
      resultado_numerico,
      resultado_booleano,
      resultado_texto
    FROM resultados_ensayos
    WHERE id_mesa = ANY($1)
    ORDER BY id_mesa, id_componente_plantilla_1, id_tipo_ensayo, fecha_medicion DESC
  `
  const resultsData = await pool.query(resultsQuery, [ids_mesas])
  
  // 3. Create results map for quick lookup
  const resultsMap = new Map()
  resultsData.rows.forEach(row => {
    const key = `${row.id_mesa}-${row.id_componente_plantilla_1}-${row.id_tipo_ensayo}`
    resultsMap.set(key, {
      numerico: row.resultado_numerico,
      booleano: row.resultado_booleano,
      texto: row.resultado_texto
    })
  })
  
  console.log(`📋 Created results map with ${resultsMap.size} entries`)
  console.log(`📋 Results data rows: ${resultsData.rows.length}`)

  // 3.5. Calculate dynamic heights for Altura hinca (id=2) based on Corte hinca (id=32)
  const calculatedHeights = new Map()

  // For each mesa and component, calculate dynamic height
  for (const row of resultsData.rows) {
    if (row.id_tipo_ensayo === 2 && row.resultado_numerico !== null) { // Altura hinca
      const mesaId = row.id_mesa
      const componentId = row.id_componente_plantilla_1
      const alturaOriginal = parseFloat(row.resultado_numerico)

      // Get all Corte hinca (id=32) values for this component
      const cortes = resultsData.rows.filter(r =>
        r.id_mesa === mesaId &&
        r.id_componente_plantilla_1 === componentId &&
        r.id_tipo_ensayo === 32 &&
        r.resultado_numerico !== null
      )

      // Calculate total cuts
      let totalCortes = 0
      cortes.forEach(corte => {
        totalCortes += parseFloat(corte.resultado_numerico)
      })

      // Calculate dynamic height: original - total cuts
      const alturaCalculada = alturaOriginal - totalCortes
      const key = `${mesaId}-${componentId}-2` // key for Altura hinca

      // Update the results map with calculated height
      resultsMap.set(key, {
        numerico: alturaCalculada,
        booleano: null,
        texto: null
      })

      calculatedHeights.set(key, {
        original: alturaOriginal,
        totalCortes: totalCortes,
        calculada: alturaCalculada
      })

      console.log(`📏 Mesa ${mesaId}, Component ${componentId}: Altura original=${alturaOriginal}, Total cortes=${totalCortes}, Altura calculada=${alturaCalculada}`)
    }
  }

  console.log(`📏 Calculated ${calculatedHeights.size} dynamic heights`)

  // 4. Create combined Excel workbook
  const combinedWorkbook = new ExcelJS.Workbook()
  
  // 5. Process each mesa
  for (const mesaTemplate of mesaTemplates) {
    const templatePath = path.join(process.cwd(), 'templates', `${mesaTemplate.nombre_plantilla}.xlsx`)
    
    // Check if template file exists
    if (!fs.existsSync(templatePath)) {
      console.warn(`⚠️ Template not found: ${templatePath}`)
      continue
    }
    
    console.log(`📋 Processing mesa ${mesaTemplate.id_mesa} with template ${mesaTemplate.nombre_plantilla}`)
    console.log(`📋 Template path: ${templatePath}`)
    
    // Load template
    const templateWorkbook = new ExcelJS.Workbook()
    await templateWorkbook.xlsx.readFile(templatePath)
    
    // Get first worksheet from template
    const templateWorksheet = templateWorkbook.worksheets[0]
    if (!templateWorksheet) {
      console.warn(`⚠️ No worksheet found in template: ${mesaTemplate.nombre_plantilla}`)
      continue
    }
    
    console.log(`📋 Worksheet found: ${templateWorksheet.name}`)
    console.log(`📋 Template has ${templateWorkbook.worksheets.length} worksheets`)
    
    // Add worksheet to combined workbook
    const newWorksheet = combinedWorkbook.addWorksheet(`Mesa_${mesaTemplate.id_mesa}`)
    
    console.log(`📋 Created new worksheet: Mesa_${mesaTemplate.id_mesa}`)
    
    // Copy template structure to new worksheet
    let templateRowCount = 0
    let templateCellCount = 0
    
    // First, copy all cells including empty ones with formatting
    for (let rowNumber = 1; rowNumber <= templateWorksheet.rowCount; rowNumber++) {
      const templateRow = templateWorksheet.getRow(rowNumber)
      if (templateRow) {
        templateRowCount++
        
        // Iterate through all columns, not just those with values
        for (let colNumber = 1; colNumber <= templateWorksheet.columnCount; colNumber++) {
          const templateCell = templateWorksheet.getCell(rowNumber, colNumber)
          const newCell = newWorksheet.getCell(rowNumber, colNumber)
          
          // Always copy the style, even for empty cells
          if (templateCell.style) {
            newCell.style = templateCell.style
            templateCellCount++
          }
          
          // Copy value if it exists
          if (templateCell.value !== null && templateCell.value !== undefined) {
            newCell.value = templateCell.value
          }
          
          // Check if cell contains placeholder JSON or @id_mesa_ct
          if (typeof templateCell.value === 'string') {
            if (templateCell.value.includes('@id_mesa_ct')) {
              // Replace @id_mesa_ct with mesa info format
              const mesaInfo = `${mesaTemplate.nombre_mesa} (CT: ${mesaTemplate.nombre_ct})`
              newCell.value = templateCell.value.replace('@id_mesa_ct', mesaInfo)
              console.log(`📋 Replaced @id_mesa_ct with: ${mesaInfo}`)
            } else if (templateCell.value.includes('{{')) {
              try {
                const placeholderMatch = templateCell.value.match(/\{\{(.*?)\}\}/)
                if (placeholderMatch) {
                  const placeholder = JSON.parse(`{${placeholderMatch[1]}}`)
                  const { id_componente_plantilla, id_tipo_ensayo } = placeholder
                  
                  // Look up result in map
                  const key = `${mesaTemplate.id_mesa}-${id_componente_plantilla}-${id_tipo_ensayo}`
                  const result = resultsMap.get(key)
                  
                  if (result) {
                    // Replace with actual value
                    let value = result.numerico || result.booleano || result.texto || ''
                    
                    // Format boolean values
                    if (result.booleano !== null) {
                      value = result.booleano ? '✓' : '✗'
                    }
                    
                    newCell.value = value
                  } else {
                    // No result found, clear placeholder
                    newCell.value = ''
                  }
                }
              } catch (error) {
                console.warn(`⚠️ Invalid JSON placeholder in cell ${rowNumber}-${colNumber}: ${templateCell.value}`)
                // Keep original value if JSON parsing fails
              }
            }
          }
        }
      }
    }
    
    console.log(`📋 Copied from template: ${templateRowCount} rows, ${templateCellCount} cells`)
    
    // Copy column widths
    templateWorksheet.columns.forEach((column, index) => {
      if (column.width) {
        newWorksheet.getColumn(index + 1).width = column.width
      }
    })
    
    // Copy row heights
    templateWorksheet.eachRow((row, rowNumber) => {
      if (row.height) {
        newWorksheet.getRow(rowNumber).height = row.height
      }
    })
    
    // Copy merged cells
    if (templateWorksheet.model && templateWorksheet.model.merges) {
      console.log(`📋 Copying ${templateWorksheet.model.merges.length} merged cells...`)
      templateWorksheet.model.merges.forEach(merge => {
        try {
          newWorksheet.mergeCells(merge)
          console.log(`📋 Merged cells: ${merge}`)
        } catch (error) {
          console.warn(`⚠️ Could not merge cells ${merge}:`, error.message)
        }
      })
    } else {
      console.log(`📋 No merged cells found in template`)
    }
    
    // Copy images from template
    if (templateWorksheet.getImages && templateWorksheet.getImages().length > 0) {
      const templateImages = templateWorksheet.getImages()
      console.log(`📋 Copying ${templateImages.length} images...`)
      
      templateImages.forEach((image, index) => {
        try {
          // Get image buffer from template workbook
          const imageBuffer = templateWorkbook.getImage(image.imageId)
          
          // Add image to combined workbook
          const imageId = combinedWorkbook.addImage({
            buffer: imageBuffer.buffer,
            extension: imageBuffer.extension
          })
          
          // Add image to worksheet with same properties
          newWorksheet.addImage(imageId, {
            tl: image.range.tl,
            br: image.range.br,
            editAs: image.range.editAs
          })
          
          console.log(`📋 Copied image ${index + 1}: ${image.range.tl.col}${image.range.tl.row} to ${image.range.br.col}${image.range.br.row}`)
        } catch (error) {
          console.warn(`⚠️ Could not copy image ${index + 1}:`, error.message)
        }
      })
    } else {
      console.log(`📋 No images found in template`)
    }
  }
  
  // 5.5. Configure page settings for all worksheets
  console.log(`📋 Configuring page settings for ${combinedWorkbook.worksheets.length} worksheets...`)
  
  combinedWorkbook.worksheets.forEach((worksheet, index) => {
    console.log(`📋 Setting page format for worksheet: ${worksheet.name}`)
    
    // Set page setup for landscape orientation and fit to one page
    worksheet.pageSetup = {
      paperSize: 9, // A4
      orientation: 'landscape',
      fitToPage: true,
      fitToWidth: 1,
      fitToHeight: 1,
      margins: {
        left: 0.5,
        right: 0.5, 
        top: 0.5,
        bottom: 0.5,
        header: 0.3,
        footer: 0.3
      },
      printArea: undefined, // Print entire sheet
      showGridLines: false
    }
    
    // Set print options
    worksheet.headerFooter = {
      oddHeader: '',
      oddFooter: ''
    }
  })
  
  // 6. Convert to PDF using LibreOffice
  console.log(`📋 Converting Excel workbook to PDF using LibreOffice...`)
  
  // Write Excel to temporary file
  const tempExcelPath = path.join(process.cwd(), `temp_${Date.now()}.xlsx`)
  await combinedWorkbook.xlsx.writeFile(tempExcelPath)
  console.log(`📋 Excel file written to: ${tempExcelPath}`)
  
  // Create temporary directory for PDF output
  const tempDir = path.join(process.cwd(), `temp_pdf_${Date.now()}`)
  fs.mkdirSync(tempDir, { recursive: true })
  
  // Use LibreOffice to convert Excel to PDF
  const { exec } = await import('child_process')
  const { promisify } = await import('util')
  const execAsync = promisify(exec)
  
  try {
    const libreOfficeCommand = `libreoffice --headless --convert-to pdf --outdir "${tempDir}" "${tempExcelPath}"`
    console.log(`📋 Running LibreOffice: ${libreOfficeCommand}`)
    
    const { stdout, stderr } = await execAsync(libreOfficeCommand)
    console.log(`📋 LibreOffice stdout: ${stdout}`)
    if (stderr) console.log(`📋 LibreOffice stderr: ${stderr}`)
    
    // Find the generated PDF file
    const pdfFileName = path.basename(tempExcelPath, '.xlsx') + '.pdf'
    const pdfPath = path.join(tempDir, pdfFileName)
    
    if (!fs.existsSync(pdfPath)) {
      throw new Error(`PDF file not generated: ${pdfPath}`)
    }
    
    console.log(`📋 PDF generated at: ${pdfPath}`)
    
    // Read the PDF file
    const finalPdfBuffer = fs.readFileSync(pdfPath)
    
    // Clean up temporary files
    fs.unlinkSync(tempExcelPath)
    fs.rmSync(tempDir, { recursive: true, force: true })
    
    console.log(`📋 Cleanup completed`)
    console.log(`📋 Excel template report generated successfully`)
    
    return finalPdfBuffer
    
  } catch (error) {
    // Clean up temporary files even if conversion fails
    if (fs.existsSync(tempExcelPath)) fs.unlinkSync(tempExcelPath)
    if (fs.existsSync(tempDir)) fs.rmSync(tempDir, { recursive: true, force: true })
    throw error
  }
}

// Cache para las claves públicas de Keycloak
let keycloakJWKS: jose.JSONWebKeySet | null = null;
let jwksLastFetched = 0;
const JWKS_CACHE_DURATION = 300000; // 5 minutos

async function getKeycloakJWKS(): Promise<jose.JSONWebKeySet> {
  const now = Date.now();
  
  if (keycloakJWKS && (now - jwksLastFetched) < JWKS_CACHE_DURATION) {
    return keycloakJWKS;
  }

  try {
    const keycloakUrl = process.env.KEYCLOAK_INTERNAL_URL || 'http://127.0.0.1:8080'
    const realm = process.env.KEYCLOAK_REALM || 'master'
    const certsUrl = `${keycloakUrl}/auth/realms/${realm}/protocol/openid-connect/certs`
    
    console.log('🔐 Obteniendo JWKS de:', certsUrl);
    
    const response = await fetch(certsUrl);
    
    if (!response.ok) {
      throw new Error(`Error obteniendo JWKS: ${response.status} ${response.statusText}`);
    }
    
    keycloakJWKS = await response.json();
    jwksLastFetched = now;
    
    console.log('✅ JWKS obtenido correctamente');
    return keycloakJWKS as jose.JSONWebKeySet;
    
  } catch (error) {
    console.error('❌ Error obteniendo JWKS:', error);
    throw new Error('No se pudieron obtener las claves de Keycloak');
  }
}

async function validateKeycloakToken(token: string): Promise<any> {
  try {
    console.log('🔐 Validando token...');
    
    const jwks = await getKeycloakJWKS();
    const localJWKS = jose.createLocalJWKSet(jwks);
    
    const { payload } = await jose.jwtVerify(token, localJWKS, {
      issuer: undefined,
      audience: undefined,
    });

    console.log('✅ Token validado correctamente');
    console.log('🔐 Usuario:', payload.preferred_username || payload.sub);
    
    return payload;
    
  } catch (error: any) {
    console.error('❌ Error validando token:', error.message);
    throw new Error('Token inválido');
  }
}

// In-memory store for PDF generation jobs
const pdfJobs = new Map<string, {
  status: 'pending' | 'processing' | 'completed' | 'error',
  result?: Buffer,
  error?: string,
  startTime: Date
}>()

// Start PDF generation (async)
app.post('/api/reports/pdf/:inspectionId/start', authMiddleware, async (c) => {
  const inspectionId = c.req.param('inspectionId')
  const jobId = `pdf-${inspectionId}-${Date.now()}`
  
  // Create job entry
  pdfJobs.set(jobId, {
    status: 'pending',
    startTime: new Date()
  })
  
  // Start async generation
  generatePDFAsync(jobId, inspectionId)
  
  return c.json({ jobId, status: 'pending' })
})

// Check PDF generation status
app.get('/api/reports/pdf/status/:jobId', authMiddleware, async (c) => {
  const jobId = c.req.param('jobId')
  const job = pdfJobs.get(jobId)
  
  if (!job) {
    return c.json({ error: 'Job not found' }, 404)
  }
  
  return c.json({
    status: job.status,
    startTime: job.startTime,
    error: job.error
  })
})

// Download completed PDF
app.get('/api/reports/pdf/download/:jobId', authMiddleware, async (c) => {
  const jobId = c.req.param('jobId')
  const job = pdfJobs.get(jobId)
  
  if (!job) {
    return c.json({ error: 'Job not found' }, 404)
  }
  
  if (job.status !== 'completed') {
    return c.json({ error: 'PDF not ready yet', status: job.status }, 400)
  }
  
  if (!job.result) {
    return c.json({ error: 'PDF result not available' }, 500)
  }
  
  // Clean up job after successful download
  pdfJobs.delete(jobId)
  
  const inspectionId = jobId.split('-')[1]
  c.header('Content-Type', 'application/pdf')
  c.header('Content-Disposition', `attachment; filename="informe-inspeccion-${inspectionId}.pdf"`)
  return c.body(job.result)
})

// Async PDF generation function
async function generatePDFAsync(jobId: string, inspectionId: string) {
  try {
    console.log(`🔍 Starting async PDF generation for inspection ${inspectionId}, job ${jobId}`)
    
    // Update job status
    const job = pdfJobs.get(jobId)
    if (job) {
      job.status = 'processing'
    }
    
    // Get report data
    const reportData = await generateReportData(inspectionId)
    if (!reportData) {
      throw new Error('Inspection not found or no data available')
    }
    
    console.log(`📄 HTML generation for job ${jobId}, mesas: ${reportData.mesas.length}`)
    
    // Debug: Verify data matches ReportView format
    let totalComponents = 0;
    let totalResults = 0;
    let falseCount = 0;
    let trueCount = 0;
    
    reportData.mesas.forEach(mesa => {
      totalComponents += mesa.components?.length || 0;
      totalResults += mesa.results?.length || 0;
      
      mesa.results?.forEach(result => {
        if (result.resultado_booleano !== null && result.resultado_booleano !== undefined) {
          if (result.resultado_booleano === false || result.resultado_booleano === 'false' || result.resultado_booleano === 0) {
            falseCount++;
          } else if (result.resultado_booleano === true || result.resultado_booleano === 'true' || result.resultado_booleano === 1) {
            trueCount++;
          }
        }
      });
    });
    
    console.log(`[PDF-REPORTVIEW] Total: ${totalComponents} components, ${totalResults} results, ${trueCount} true, ${falseCount} false`);
    
    // Sample data from first mesa
    if (reportData.mesas.length > 0) {
      const firstMesa = reportData.mesas[0];
      console.log(`[PDF-REPORTVIEW] First mesa sample:`, {
        mesa_id: firstMesa.id_mesa,
        components_sample: firstMesa.components?.slice(0, 2).map(c => ({id: c.id_componente, type: c.tipo_elemento})),
        results_sample: firstMesa.results?.slice(0, 2).map(r => ({comp: r.id_componente_plantilla_1, test: r.id_tipo_ensayo, bool: r.resultado_booleano}))
      });
    }
    
    // Generate HTML
    const htmlContent = generateReportHTML(reportData)
    
    // Generate PDF with Puppeteer - optimized for large documents
    const browser = await puppeteer.launch({ 
      headless: true,
      args: [
        '--no-sandbox', 
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--disable-web-security',
        '--disable-features=TranslateUI',
        '--disable-accelerated-2d-canvas',
        '--no-first-run',
        '--no-zygote',
        '--memory-pressure-off',
        '--disable-background-timer-throttling',
        '--disable-backgrounding-occluded-windows',
        '--disable-renderer-backgrounding',
        '--max_old_space_size=8192'
      ]
    })
    
    const page = await browser.newPage()
    
    // Set very long timeouts for large documents
    page.setDefaultNavigationTimeout(3600000) // 60 minutes
    page.setDefaultTimeout(3600000) // 60 minutes
    
    // Optimize memory usage
    await page.evaluateOnNewDocument(() => {
      window.requestIdleCallback = window.requestIdleCallback || function(cb) { return setTimeout(cb, 1) }
    })
    
    console.log(`🌐 Setting HTML content for job ${jobId}...`)
    
    // Set content with optimized settings
    await page.setContent(htmlContent, { 
      waitUntil: 'domcontentloaded',
      timeout: 3600000 // 60 minutes
    })
    
    console.log(`🖨️ Generating PDF for job ${jobId}...`)
    
    // Generate PDF with optimizations for large documents
    const pdfBuffer = await page.pdf({
      format: 'A4',
      landscape: false,
      printBackground: true,
      margin: { top: '10mm', bottom: '10mm', left: '10mm', right: '10mm' },
      displayHeaderFooter: false,
      preferCSSPageSize: false,
      timeout: 7200000 // 120 minutes for PDF generation
    })
    
    await browser.close()
    
    console.log(`✅ PDF generated successfully for job ${jobId}, size: ${pdfBuffer.length} bytes`)
    
    // Update job with result
    const finalJob = pdfJobs.get(jobId)
    if (finalJob) {
      finalJob.status = 'completed'
      finalJob.result = pdfBuffer
    }
    
  } catch (error) {
    console.error(`❌ Error generating PDF for job ${jobId}:`, error)
    
    // Update job with error
    const job = pdfJobs.get(jobId)
    if (job) {
      job.status = 'error'
      job.error = error instanceof Error ? error.message : 'Unknown error'
    }
  }
}

// Clean up old jobs periodically (every 30 minutes)
setInterval(() => {
  const now = new Date()
  for (const [jobId, job] of pdfJobs.entries()) {
    const ageInMinutes = (now.getTime() - job.startTime.getTime()) / (1000 * 60)
    // Remove jobs older than 2 hours
    if (ageInMinutes > 120) {
      pdfJobs.delete(jobId)
      console.log(`🧹 Cleaned up old PDF job: ${jobId}`)
    }
  }
}, 30 * 60 * 1000)


// New polling-based Excel Template PDF Report Generator endpoints

// Start Excel report generation job
app.post('/api/generar-informe-plantillas/start', authMiddleware, async (c) => {
  try {
    const { ids_mesas } = await c.req.json()
    
    if (!Array.isArray(ids_mesas) || ids_mesas.length === 0) {
      return c.json({ error: 'ids_mesas must be a non-empty array' }, 400)
    }

    const jobId = generateJobId()
    
    // Create job in pending state
    const job: ReportJob = {
      id: jobId,
      status: 'pending',
      data: { ids_mesas },
      createdAt: new Date()
    }
    
    reportJobs.set(jobId, job)
    
    console.log(`📋 Started Excel report job ${jobId} for ${ids_mesas.length} mesas`)
    
    // Start async processing
    processExcelReportJob(jobId).catch(error => {
      console.error(`📋 Job ${jobId} failed:`, error)
      const failedJob = reportJobs.get(jobId)
      if (failedJob) {
        failedJob.status = 'error'
        failedJob.error = error.message
        failedJob.completedAt = new Date()
      }
    })
    
    return c.json({ jobId })
  } catch (error) {
    console.error('Error starting Excel report job:', error)
    return c.json({ error: 'Failed to start Excel report job', details: error.message }, 500)
  }
})

// Check Excel report job status
app.get('/api/generar-informe-plantillas/status/:jobId', authMiddleware, async (c) => {
  try {
    const jobId = c.req.param('jobId')
    const job = reportJobs.get(jobId)
    
    if (!job) {
      return c.json({ error: 'Job not found' }, 404)
    }
    
    return c.json({ 
      status: job.status,
      error: job.error || null,
      createdAt: job.createdAt,
      completedAt: job.completedAt || null
    })
  } catch (error) {
    console.error('Error checking Excel report job status:', error)
    return c.json({ error: 'Failed to check job status', details: error.message }, 500)
  }
})

// Download completed Excel report
app.get('/api/generar-informe-plantillas/download/:jobId', authMiddleware, async (c) => {
  try {
    const jobId = c.req.param('jobId')
    const job = reportJobs.get(jobId)
    
    if (!job) {
      return c.json({ error: 'Job not found' }, 404)
    }
    
    if (job.status !== 'completed') {
      return c.json({ error: 'Job not completed yet' }, 400)
    }
    
    if (!job.result) {
      return c.json({ error: 'No result available' }, 500)
    }
    
    // Return the PDF
    return new Response(job.result as any, {
      headers: {
        'Content-Type': 'application/pdf',
        'Content-Disposition': `attachment; filename="informe-plantillas-${new Date().toISOString().split('T')[0]}.pdf"`
      }
    })
  } catch (error) {
    console.error('Error downloading Excel report:', error)
    return c.json({ error: 'Failed to download report', details: error.message }, 500)
  }
})

// Async job processing function
async function processExcelReportJob(jobId: string) {
  const job = reportJobs.get(jobId)
  if (!job) {
    throw new Error(`Job ${jobId} not found`)
  }
  
  try {
    console.log(`📋 Processing Excel report job ${jobId}...`)
    job.status = 'processing'
    
    // Generate the report using the extracted function
    const pdfBuffer = await generateExcelTemplateReport(job.data.ids_mesas)
    
    // Store result
    job.result = pdfBuffer
    job.status = 'completed'
    job.completedAt = new Date()
    
    console.log(`📋 Excel report job ${jobId} completed successfully`)
  } catch (error) {
    console.error(`📋 Excel report job ${jobId} failed:`, error)
    job.status = 'error'
    job.error = error.message
    job.completedAt = new Date()
    throw error
  }
}

// POT Template Report Generator Function
async function generatePOTTemplateReport(ids_mesas: number[]): Promise<Buffer> {
  console.log(`📋 Generating POT template report for mesas: ${ids_mesas.join(', ')}`)
  
  // 1. Get components with POT test results for selected mesas
  const componentsQuery = `
    SELECT DISTINCT 
      m.id_mesa, 
      m.nombre_mesa, 
      ct.nombre_ct,
      pc.id_componente,
      pc.tipo_elemento,
      pc.tipo_perfil,
      pc.coord_x,
      pc.coord_y,
      pc.descripcion_punto_montaje
    FROM mesas m
    JOIN mesa_plantillas mp ON m.id_plantilla = mp.id_plantilla
    JOIN plantilla_componentes pc ON mp.id_plantilla = pc.id_plantilla
    JOIN cts ct ON m.id_ct = ct.id_ct
    JOIN resultados_ensayos r ON r.id_mesa = m.id_mesa AND r.id_componente_plantilla_1 = pc.id_componente
    JOIN tipos_ensayo te ON r.id_tipo_ensayo = te.id_tipo_ensayo
    WHERE m.id_mesa = ANY($1) 
      AND pc.tipo_perfil IS NOT NULL 
      AND te.grupo_ensayo = 'POT'
    ORDER BY m.id_mesa, pc.id_componente
  `
  const componentsResult = await pool.query(componentsQuery, [ids_mesas])
  const componentsWithPOT = componentsResult.rows
  
  console.log(`📋 Found components with POT tests:`, componentsWithPOT.length)
  console.log(`📋 Components details:`, componentsWithPOT)
  
  if (componentsWithPOT.length === 0) {
    throw new Error('No se encontraron componentes con ensayos POT para las mesas seleccionadas')
  }
  
  // 2. Get latest test results for all components (POT ensayos only)
  const resultsQuery = `
    SELECT DISTINCT ON (r.id_mesa, r.id_componente_plantilla_1, r.id_tipo_ensayo)
      r.id_mesa,
      r.id_componente_plantilla_1,
      r.id_tipo_ensayo,
      r.resultado_numerico,
      r.resultado_booleano,
      r.resultado_texto,
      r.comentario,
      r.fecha_medicion,
      te.grupo_ensayo
    FROM resultados_ensayos r
    JOIN tipos_ensayo te ON r.id_tipo_ensayo = te.id_tipo_ensayo
    WHERE r.id_mesa = ANY($1) AND te.grupo_ensayo = 'POT'
    ORDER BY r.id_mesa, r.id_componente_plantilla_1, r.id_tipo_ensayo, r.fecha_medicion DESC
  `
  const resultsData = await pool.query(resultsQuery, [ids_mesas])
  
  // 3. Create results map for quick lookup
  const resultsMap = new Map()
  resultsData.rows.forEach(row => {
    const key = `${row.id_mesa}-${row.id_componente_plantilla_1}-${row.id_tipo_ensayo}`
    resultsMap.set(key, {
      numerico: row.resultado_numerico,
      booleano: row.resultado_booleano,
      texto: row.resultado_texto,
      comentario: row.comentario,
      fecha_medicion: row.fecha_medicion
    })
  })
  
  console.log(`📋 Created POT results map with ${resultsMap.size} entries`)
  
  // 4. Create combined Excel workbook
  const combinedWorkbook = new ExcelJS.Workbook()
  
  // 5. Initialize inspection counter for correlative numbering
  let inspectionCounter = 0
  
  // 6. Process each component that has POT tests
  for (const component of componentsWithPOT) {
    const templatePath = path.join(process.cwd(), 'templates', `${component.tipo_perfil}.xlsx`)
    
    // Check if template file exists
    if (!fs.existsSync(templatePath)) {
      console.warn(`⚠️ POT Template not found: ${templatePath}`)
      continue
    }
    
    console.log(`📋 Processing component ${component.id_componente} from mesa ${component.id_mesa} with POT template ${component.tipo_perfil}`)
    
    // Load template
    const templateWorkbook = new ExcelJS.Workbook()
    await templateWorkbook.xlsx.readFile(templatePath)
    
    // Get first worksheet from template
    const templateWorksheet = templateWorkbook.worksheets[0]
    if (!templateWorksheet) {
      console.warn(`⚠️ No worksheet found in POT template: ${component.tipo_perfil}`)
      continue
    }
    
    // Add worksheet to combined workbook - one sheet per component
    const newWorksheet = combinedWorkbook.addWorksheet(`Mesa_${component.nombre_mesa}_Comp_${component.id_componente}`)
    
    // Increment inspection counter for this sheet
    inspectionCounter++
    
    console.log(`📋 Created new POT worksheet: Mesa_${component.nombre_mesa}_Comp_${component.id_componente} (Inspection #${inspectionCounter})`)
    
    // Copy template structure to new worksheet (same as HINCAS but with POT-specific processing)
    for (let rowNumber = 1; rowNumber <= templateWorksheet.rowCount; rowNumber++) {
      const templateRow = templateWorksheet.getRow(rowNumber)
      if (templateRow) {
        for (let colNumber = 1; colNumber <= templateWorksheet.columnCount; colNumber++) {
          const templateCell = templateWorksheet.getCell(rowNumber, colNumber)
          const newCell = newWorksheet.getCell(rowNumber, colNumber)
          
          // Copy style
          if (templateCell.style) {
            newCell.style = templateCell.style
          }
          
          // Copy value if it exists
          if (templateCell.value !== null && templateCell.value !== undefined) {
            newCell.value = templateCell.value
          }
          
          // Check if cell contains POT-specific placeholders
          if (typeof templateCell.value === 'string') {
            const cellValue = templateCell.value
            
            // Replace common placeholders using THIS specific component's data
            if (cellValue.includes('[fecha]')) {
              // Get any result from this component to extract the date
              const componentResultKey = Array.from(resultsMap.keys()).find(key => 
                key.startsWith(`${component.id_mesa}-${component.id_componente}-`)
              )
              const fechaResult = componentResultKey ? resultsMap.get(componentResultKey) : null
              const fecha = fechaResult?.fecha_medicion ? new Date(fechaResult.fecha_medicion).toLocaleDateString('es-ES') : ''
              newCell.value = cellValue.replace('[fecha]', fecha)
            } else if (cellValue.includes('[perfil]')) {
              newCell.value = cellValue.replace('[perfil]', component.tipo_perfil)
            } else if (cellValue.includes('[hinca]')) {
              const hincaInfo = `Mesa: ${component.nombre_mesa}, ${component.nombre_ct} - ${component.descripcion_punto_montaje}`
              newCell.value = cellValue.replace('[hinca]', hincaInfo)
            } else if (cellValue.includes('[inspeccion]')) {
              newCell.value = cellValue.replace('[inspeccion]', inspectionCounter.toString())
            } else if (cellValue.includes('[profundidad_hinca]')) {
              const result = resultsMap.get(`${component.id_mesa}-${component.id_componente}-21`)
              newCell.value = cellValue.replace('[profundidad_hinca]', result?.numerico || '')
            } else if (cellValue.includes('[diametro_taladro]')) {
              const result = resultsMap.get(`${component.id_mesa}-${component.id_componente}-22`)
              newCell.value = cellValue.replace('[diametro_taladro]', result?.numerico || '')
            } else if (cellValue.includes('[altura_aplicacion_carga]')) {
              const result = resultsMap.get(`${component.id_mesa}-${component.id_componente}-23`)
              newCell.value = cellValue.replace('[altura_aplicacion_carga]', result?.numerico || '')
            } else if (cellValue.includes('[v_carga_aplicada]')) {
              const result = resultsMap.get(`${component.id_mesa}-${component.id_componente}-24`)
              newCell.value = cellValue.replace('[v_carga_aplicada]', result?.numerico || '')
            } else if (cellValue.includes('[v_lect_comparador_inf_T1]')) {
              const result = resultsMap.get(`${component.id_mesa}-${component.id_componente}-25`)
              newCell.value = cellValue.replace('[v_lect_comparador_inf_T1]', result?.numerico || '')
            } else if (cellValue.includes('[v_lect_comparador_inf_T2]')) {
              const result = resultsMap.get(`${component.id_mesa}-${component.id_componente}-26`)
              newCell.value = cellValue.replace('[v_lect_comparador_inf_T2]', result?.numerico || '')
            } else if (cellValue.includes('[v_comentario]')) {
              // Leer comentario de tipo_ensayo=36 (Comentario POT Vertical)
              const result = resultsMap.get(`${component.id_mesa}-${component.id_componente}-36`)
              newCell.value = cellValue.replace('[v_comentario]', result?.texto || '')
            } else if (cellValue.includes('[v_valido]')) {
              // Leer validez de tipo_ensayo=34 (Validez POT vertical)
              const result = resultsMap.get(`${component.id_mesa}-${component.id_componente}-34`)
              let validezTexto = ''
              if (result?.booleano === true) {
                validezTexto = 'Sí'
              } else if (result?.booleano === false) {
                validezTexto = 'No'
              }
              newCell.value = cellValue.replace('[v_valido]', validezTexto)
            } else if (cellValue.includes('[c_carga_aplicada]')) {
              const result = resultsMap.get(`${component.id_mesa}-${component.id_componente}-31`)
              newCell.value = cellValue.replace('[c_carga_aplicada]', result?.numerico || '')
            } else if (cellValue.includes('[c_lect_comparador_inf_T1]')) {
              const result = resultsMap.get(`${component.id_mesa}-${component.id_componente}-29`)
              newCell.value = cellValue.replace('[c_lect_comparador_inf_T1]', result?.numerico || '')
            } else if (cellValue.includes('[c_lect_comparador_inf_T2]')) {
              const result = resultsMap.get(`${component.id_mesa}-${component.id_componente}-26`)
              newCell.value = cellValue.replace('[c_lect_comparador_inf_T2]', result?.numerico || '')
            } else if (cellValue.includes('[c_valido]')) {
              // Leer validez de tipo_ensayo=35 (Validez POT cortante)
              const result = resultsMap.get(`${component.id_mesa}-${component.id_componente}-35`)
              let validezTexto = ''
              if (result?.booleano === true) {
                validezTexto = 'Sí'
              } else if (result?.booleano === false) {
                validezTexto = 'No'
              }
              newCell.value = cellValue.replace('[c_valido]', validezTexto)
            } else if (cellValue.includes('[c_comentario]')) {
              // Concatenar comentarios de medidas cortantes (c) con salto de línea
              const cComments = []
              const ids_tipos_c = [31, 29, 26] // tipos de ensayo cortantes (actualizado 27→31)
              ids_tipos_c.forEach(id_tipo => {
                const result = resultsMap.get(`${component.id_mesa}-${component.id_componente}-${id_tipo}`)
                if (result?.comentario) {
                  cComments.push(result.comentario)
                }
              })
              newCell.value = cellValue.replace('[c_comentario]', cComments.join('\n'))
            }
          }
        }
      }
    }
    
    // Copy column widths, row heights, and merged cells (same as HINCAS)
    templateWorksheet.columns.forEach((column, index) => {
      if (column.width) {
        newWorksheet.getColumn(index + 1).width = column.width
      }
    })
    
    templateWorksheet.eachRow((row, rowNumber) => {
      if (row.height) {
        newWorksheet.getRow(rowNumber).height = row.height
      }
    })
    
    if (templateWorksheet.model && templateWorksheet.model.merges) {
      templateWorksheet.model.merges.forEach(merge => {
        try {
          newWorksheet.mergeCells(merge)
        } catch (error) {
          console.warn(`⚠️ Could not merge cells ${merge}:`, error.message)
        }
      })
    }
    
    // Copy images if any
    if (templateWorksheet.getImages && templateWorksheet.getImages().length > 0) {
      const templateImages = templateWorksheet.getImages()
      templateImages.forEach((image, index) => {
        try {
          const imageBuffer = templateWorkbook.getImage(image.imageId)
          const imageId = combinedWorkbook.addImage({
            buffer: imageBuffer.buffer,
            extension: imageBuffer.extension
          })
          newWorksheet.addImage(imageId, {
            tl: image.range.tl,
            br: image.range.br,
          })
        } catch (error) {
          console.warn(`⚠️ Could not copy image ${index}:`, error.message)
        }
      })
    }
  }
  
  // 6. Set page setup for each worksheet - LANDSCAPE and fit to one page
  combinedWorkbook.eachSheet((worksheet) => {
    worksheet.pageSetup = {
      orientation: 'landscape',  // Formato apaisado
      paperSize: 9, // A4
      margins: {
        left: 0.5,    // Márgenes más pequeños para aprovechar espacio
        right: 0.5,
        top: 0.5,
        bottom: 0.5,
        header: 0.2,
        footer: 0.2
      },
      printArea: undefined, // Print entire sheet
      showGridLines: false,
      fitToPage: true,      // Ajustar a página
      fitToWidth: 1,        // Ajustar ancho a 1 página
      fitToHeight: 1,       // Ajustar alto a 1 página
      scale: undefined      // No usar escala fija cuando se usa fitToPage
    }
    
    // Set print options
    worksheet.headerFooter = {
      oddHeader: '',
      oddFooter: ''
    }
  })
  
  // 7. Convert to PDF using LibreOffice
  console.log(`📋 Converting POT Excel workbook to PDF using LibreOffice...`)
  
  // Write Excel to temporary file
  const tempExcelPath = path.join(process.cwd(), `temp_pot_${Date.now()}.xlsx`)
  await combinedWorkbook.xlsx.writeFile(tempExcelPath)
  console.log(`📋 POT Excel file written to: ${tempExcelPath}`)
  
  // Create temporary directory for PDF output
  const tempDir = path.join(process.cwd(), `temp_pot_pdf_${Date.now()}`)
  fs.mkdirSync(tempDir, { recursive: true })
  
  // Use LibreOffice to convert Excel to PDF
  const { exec } = await import('child_process')
  const { promisify } = await import('util')
  const execAsync = promisify(exec)
  
  try {
    const libreOfficeCommand = `libreoffice --headless --convert-to pdf --outdir "${tempDir}" "${tempExcelPath}"`
    console.log(`📋 Running LibreOffice for POT: ${libreOfficeCommand}`)
    
    const { stdout, stderr } = await execAsync(libreOfficeCommand)
    console.log(`📋 LibreOffice POT stdout: ${stdout}`)
    if (stderr) console.log(`📋 LibreOffice POT stderr: ${stderr}`)
    
    // Find the generated PDF file
    const pdfFileName = path.basename(tempExcelPath, '.xlsx') + '.pdf'
    const pdfPath = path.join(tempDir, pdfFileName)
    
    if (!fs.existsSync(pdfPath)) {
      throw new Error(`POT PDF file not generated: ${pdfPath}`)
    }
    
    console.log(`📋 POT PDF generated at: ${pdfPath}`)
    
    // Read the PDF file
    const finalPdfBuffer = fs.readFileSync(pdfPath)
    
    // Clean up temporary files and directories
    try {
      fs.unlinkSync(tempExcelPath)
      fs.unlinkSync(pdfPath)
      fs.rmdirSync(tempDir)
    } catch (error) {
      console.warn(`📋 Warning: Could not clean up POT temp files:`, error.message)
    }
    
    console.log(`📋 POT PDF conversion completed successfully`)
    return finalPdfBuffer
    
  } catch (error) {
    console.error(`📋 Error converting POT Excel to PDF:`, error)
    
    // Clean up on error
    try {
      if (fs.existsSync(tempExcelPath)) fs.unlinkSync(tempExcelPath)
      if (fs.existsSync(tempDir)) {
        const files = fs.readdirSync(tempDir)
        files.forEach(file => fs.unlinkSync(path.join(tempDir, file)))
        fs.rmdirSync(tempDir)
      }
    } catch (cleanupError) {
      console.warn(`📋 Warning: Could not clean up POT temp files after error:`, cleanupError.message)
    }
    
    throw error
  }
}

// Excel Template PDF Report Generator (original synchronous endpoint for backward compatibility)
app.post('/api/generar-informe-plantillas', authMiddleware, async (c) => {
  try {
    const { ids_mesas } = await c.req.json()
    
    if (!Array.isArray(ids_mesas) || ids_mesas.length === 0) {
      return c.json({ error: 'ids_mesas must be a non-empty array' }, 400)
    }
    
    console.log(`📋 [SYNC] Generating Excel template report for mesas: ${ids_mesas.join(', ')}`)
    
    // Use the extracted function for report generation
    const finalPdfBuffer = await generateExcelTemplateReport(ids_mesas)
    
    // Return PDF
    return new Response(finalPdfBuffer as any, {
      headers: {
        'Content-Type': 'application/pdf',
        'Content-Disposition': `attachment; filename="informe-plantillas-${new Date().toISOString().split('T')[0]}.pdf"`
      }
    })
    
  } catch (error) {
    console.error('Error generating Excel template report:', error)
    return c.json({ error: 'Failed to generate Excel template report', details: error.message }, 500)
  }
})

// POT Template PDF Report Generator endpoints
// Start POT report generation job
app.post('/api/generar-informe-pot-plantillas/start', authMiddleware, async (c) => {
  try {
    const { ids_mesas } = await c.req.json()
    
    if (!Array.isArray(ids_mesas) || ids_mesas.length === 0) {
      return c.json({ error: 'ids_mesas must be a non-empty array' }, 400)
    }
    const jobId = generateJobId()
    
    // Create job in pending state
    const job: ReportJob = {
      id: jobId,
      status: 'pending',
      data: { ids_mesas },
      createdAt: new Date()
    }
    
    reportJobs.set(jobId, job)
    
    console.log(`📋 Started POT report job ${jobId} for ${ids_mesas.length} mesas`)
    
    // Start async processing
    processPOTReportJob(jobId).catch(error => {
      console.error(`📋 POT Job ${jobId} failed:`, error)
      const failedJob = reportJobs.get(jobId)
      if (failedJob) {
        failedJob.status = 'error'
        failedJob.error = error.message
        failedJob.completedAt = new Date()
      }
    })
    
    return c.json({ jobId })
  } catch (error) {
    console.error('Error starting POT report job:', error)
    return c.json({ error: 'Failed to start POT report job', details: error.message }, 500)
  }
})

// Check POT report job status
app.get('/api/generar-informe-pot-plantillas/status/:jobId', authMiddleware, async (c) => {
  try {
    const jobId = c.req.param('jobId')
    const job = reportJobs.get(jobId)
    
    if (!job) {
      return c.json({ error: 'Job not found' }, 404)
    }
    
    return c.json({ 
      status: job.status,
      error: job.error || null,
      createdAt: job.createdAt,
      completedAt: job.completedAt || null
    })
  } catch (error) {
    console.error('Error checking POT report job status:', error)
    return c.json({ error: 'Failed to check job status', details: error.message }, 500)
  }
})

// Download completed POT report
app.get('/api/generar-informe-pot-plantillas/download/:jobId', authMiddleware, async (c) => {
  try {
    const jobId = c.req.param('jobId')
    const job = reportJobs.get(jobId)
    
    if (!job) {
      return c.json({ error: 'Job not found' }, 404)
    }
    
    if (job.status !== 'completed') {
      return c.json({ error: 'Job not completed yet' }, 400)
    }
    
    if (!job.result) {
      return c.json({ error: 'No result available' }, 500)
    }
    
    // Return the PDF
    return new Response(job.result as any, {
      headers: {
        'Content-Type': 'application/pdf',
        'Content-Disposition': `attachment; filename="informe-pot-${new Date().toISOString().split('T')[0]}.pdf"`
      }
    })
  } catch (error) {
    console.error('Error downloading POT report:', error)
    return c.json({ error: 'Failed to download report', details: error.message }, 500)
  }
})

// POT Template PDF Report Generator (synchronous endpoint for backward compatibility)
app.post('/api/generar-informe-pot-plantillas', authMiddleware, async (c) => {
  try {
    const { ids_mesas } = await c.req.json()
    
    if (!Array.isArray(ids_mesas) || ids_mesas.length === 0) {
      return c.json({ error: 'ids_mesas must be a non-empty array' }, 400)
    }
    
    console.log(`📋 [SYNC] Generating POT template report for mesas: ${ids_mesas.join(', ')}`)
    
    // Use the extracted function for report generation
    const finalPdfBuffer = await generatePOTTemplateReport(ids_mesas)
    
    // Return PDF
    return new Response(finalPdfBuffer as any, {
      headers: {
        'Content-Type': 'application/pdf',
        'Content-Disposition': `attachment; filename="informe-pot-${new Date().toISOString().split('T')[0]}.pdf"`
      }
    })
    
  } catch (error) {
    console.error('Error generating POT template report:', error)
    return c.json({ error: 'Failed to generate POT template report', details: error.message }, 500)
  }
})

// Async POT job processing function
async function processPOTReportJob(jobId: string) {
  const job = reportJobs.get(jobId)
  if (!job) {
    throw new Error(`Job ${jobId} not found`)
  }
  
  try {
    console.log(`📋 Processing POT report job ${jobId}...`)
    job.status = 'processing'
    
    // Generate the report using the POT function
    const pdfBuffer = await generatePOTTemplateReport(job.data.ids_mesas)
    
    // Store result
    job.result = pdfBuffer
    job.status = 'completed'
    job.completedAt = new Date()
    
    console.log(`📋 POT report job ${jobId} completed successfully`)
  } catch (error) {
    console.error(`📋 POT report job ${jobId} failed:`, error)
    job.status = 'error'
    job.error = error.message
    job.completedAt = new Date()
    throw error
  }
}

// Report generation endpoints
app.get('/api/inspecciones', authMiddleware, async (c) => {
  try {
    console.log('📋 Fetching all inspections...')
    
    const query = `
      SELECT 
        id_inspeccion,
        id_usuario,
        fecha_inicio,
        fecha_fin,
        descripcion,
        estado
      FROM inspecciones
      ORDER BY fecha_inicio DESC
      LIMIT 50
    `
    
    const result = await pool.query(query)
    console.log(`📋 Found ${result.rows.length} inspections`)
    return c.json(result.rows)
    
  } catch (error) {
    console.error('Error fetching inspections:', error)
    return c.json({ error: 'Failed to fetch inspections' }, 500)
  }
})

app.get('/api/inspecciones/:id/mesas', authMiddleware, async (c) => {
  try {
    const id_inspeccion = c.req.param('id')
    console.log(`📋 Fetching mesas for inspection ${id_inspeccion}...`)
    
    const query = `
      SELECT DISTINCT 
        m.id_mesa,
        m.id_ct,
        m.nombre_mesa,
        m.coord_x,
        m.coord_y,
        ct.nombre_ct
      FROM mesas m
      JOIN resultados_ensayos re ON m.id_mesa = re.id_mesa
      LEFT JOIN cts ct ON m.id_ct = ct.id_ct
      WHERE re.id_inspeccion = $1
      ORDER BY m.id_mesa
    `
    
    const result = await pool.query(query, [id_inspeccion])
    console.log(`📋 Found ${result.rows.length} mesas for inspection ${id_inspeccion}`)
    return c.json(result.rows)
    
  } catch (error) {
    console.error('Error fetching inspection mesas:', error)
    return c.json({ error: 'Failed to fetch inspection mesas' }, 500)
  }
})

app.get('/api/inspecciones/:id/report-data', authMiddleware, async (c) => {
  try {
    const id_inspeccion = c.req.param('id')
    console.log(`📋 Generating report data for inspection ${id_inspeccion}...`)
    
    // Get inspection details
    const inspectionQuery = `
      SELECT 
        id_inspeccion,
        id_usuario,
        fecha_inicio,
        fecha_fin,
        descripcion,
        estado
      FROM inspecciones
      WHERE id_inspeccion = $1
    `
    const inspectionResult = await pool.query(inspectionQuery, [id_inspeccion])
    const inspection = inspectionResult.rows[0]
    
    if (!inspection) {
      return c.json({ error: 'Inspection not found' }, 404)
    }
    
    // Get mesas with their test results
    const mesasQuery = `
      SELECT DISTINCT 
        m.id_mesa,
        m.id_ct,
        m.nombre_mesa,
        m.coord_x,
        m.coord_y,
        ct.nombre_ct
      FROM mesas m
      JOIN resultados_ensayos re ON m.id_mesa = re.id_mesa
      LEFT JOIN cts ct ON m.id_ct = ct.id_ct
      WHERE re.id_inspeccion = $1
      ORDER BY m.id_mesa
    `
    const mesasResult = await pool.query(mesasQuery, [id_inspeccion])
    const mesas = mesasResult.rows
    
    // Get test results for each mesa
    const mesasWithResults = []
    for (const mesa of mesas) {
      const resultsQuery = `
        SELECT 
          re.id_resultado,
          re.resultado_numerico,
          re.resultado_booleano,
          re.resultado_texto,
          re.fecha_medicion,
          re.comentario,
          te.nombre_ensayo,
          te.tipo_resultado,
          te.unidad_medida,
          pc.descripcion_punto_montaje,
          pc.coord_x as componente_x,
          pc.coord_y as componente_y
        FROM resultados_ensayos re
        JOIN tipos_ensayo te ON re.id_tipo_ensayo = te.id_tipo_ensayo
        LEFT JOIN plantilla_componentes pc ON re.id_componente_plantilla_1 = pc.id_componente
        WHERE re.id_inspeccion = $1 AND re.id_mesa = $2
        ORDER BY pc.orden_prioridad ASC, te.orden_prioridad ASC
      `
      const resultsResult = await pool.query(resultsQuery, [id_inspeccion, mesa.id_mesa])
      
      mesasWithResults.push({
        ...mesa,
        resultados: resultsResult.rows
      })
    }
    
    const reportData = {
      inspection,
      mesas: mesasWithResults,
      generated_at: new Date().toISOString()
    }
    
    console.log(`📋 Generated report data for ${mesas.length} mesas`)
    return c.json(reportData)
    
  } catch (error) {
    console.error('Error generating report data:', error)
    return c.json({ error: 'Failed to generate report data' }, 500)
  }
})

// Continue with other export endpoints

// Helper function to get all report data
async function generateReportData(inspectionId: string) {
  try {
    // Get inspection info
    const inspectionQuery = `
      SELECT * FROM inspecciones 
      WHERE id_inspeccion = $1
    `
    const inspectionResult = await pool.query(inspectionQuery, [inspectionId])
    
    if (inspectionResult.rows.length === 0) {
      return null
    }
    
    const inspection = inspectionResult.rows[0]
    
    // Get mesas with results for this inspection
    const mesasQuery = `
      SELECT DISTINCT 
        m.id_mesa,
        m.nombre_mesa,
        m.coord_x,
        m.coord_y,
        c.nombre_ct,
        mp.nombre_plantilla
      FROM mesas m
      JOIN cts c ON m.id_ct = c.id_ct
      JOIN mesa_plantillas mp ON m.id_plantilla = mp.id_plantilla
      JOIN resultados_ensayos re ON m.id_mesa = re.id_mesa
      WHERE re.id_inspeccion = $1
      ORDER BY m.id_mesa
    `
    
    const mesasResult = await pool.query(mesasQuery, [inspectionId])
    const mesas = mesasResult.rows
    
    // Get all tipos ensayo (filtered by HINCAS group)
    const tiposEnsayoQuery = `
      SELECT 
        id_tipo_ensayo,
        nombre_ensayo,
        unidad_medida,
        tipo_resultado,
        grupo_ensayo
      FROM tipos_ensayo
      WHERE grupo_ensayo = 'HINCAS'
      ORDER BY orden_prioridad ASC, nombre_ensayo
    `
    
    const tiposEnsayoResult = await pool.query(tiposEnsayoQuery)
    const tiposEnsayo = tiposEnsayoResult.rows
    
    // Get color rules
    const colorRulesQuery = `
      SELECT 
        id,
        id_tipo_ensayo,
        tipo_condicion,
        valor_numerico_1,
        valor_numerico_2,
        valor_booleano,
        valor_texto,
        resaltado,
        comentario,
        prioridad
      FROM reglas_resultados_ensayos
      ORDER BY prioridad ASC
    `
    
    const colorRulesResult = await pool.query(colorRulesQuery)
    const colorRules = colorRulesResult.rows
    
    // Use ReportView logic but optimized for batch processing
    console.log(`[PDF-DATA] Using ReportView-compatible logic for ${mesas.length} mesas...`)
    
    // Use the exact same logic as the working /api/mesas/:id/components endpoint
    const allMesaIds = mesas.map(m => m.id_mesa)
    
    console.log(`[PDF-DATA] Mesa IDs:`, allMesaIds)
    
    // Get all components using the same JOIN as the working endpoint
    const componentsQuery = `
      SELECT 
        m.id_mesa,
        pc.id_componente,
        pc.tipo_elemento,
        pc.coord_x,
        pc.coord_y,
        pc.descripcion_punto_montaje,
        pc.orden_prioridad
      FROM mesas m
      JOIN plantilla_componentes pc ON m.id_plantilla = pc.id_plantilla
      WHERE m.id_mesa = ANY($1)
      ORDER BY m.id_mesa, pc.orden_prioridad ASC, pc.tipo_elemento, pc.coord_x, pc.coord_y
    `
    
    console.log(`[PDF-DATA] Using working endpoint logic for components`)
    
    const componentsResult = await pool.query(componentsQuery, [allMesaIds])
    
    console.log(`[PDF-DATA] Components query returned:`, componentsResult.rows.length, 'rows')
    if (componentsResult.rows.length === 0) {
      console.log(`[PDF-DATA] ⚠️ No components found! Debugging...`)
      // Test the working endpoint logic for first mesa
      if (allMesaIds.length > 0) {
        const testQuery = `
          SELECT m.id_mesa, m.id_plantilla, pc.id_componente
          FROM mesas m
          LEFT JOIN plantilla_componentes pc ON m.id_plantilla = pc.id_plantilla
          WHERE m.id_mesa = $1
        `
        const testResult = await pool.query(testQuery, [allMesaIds[0]])
        console.log(`[PDF-DATA] Test query for mesa ${allMesaIds[0]}:`, testResult.rows)
      }
    }
    
    // Get latest test results for all mesas (ReportView logic)
    const resultsQuery = `
      WITH latest_results AS (
        SELECT 
          re.*,
          ROW_NUMBER() OVER (
            PARTITION BY re.id_mesa, re.id_componente_plantilla_1, re.id_tipo_ensayo 
            ORDER BY re.fecha_medicion DESC, re.id_resultado DESC
          ) as rn
        FROM resultados_ensayos re
        WHERE re.id_mesa = ANY($1) AND re.id_inspeccion = $2
      )
      SELECT 
        lr.id_tipo_ensayo,
        lr.id_componente_plantilla_1,
        lr.id_mesa,
        lr.resultado_numerico,
        lr.resultado_booleano,
        lr.resultado_texto,
        lr.comentario,
        lr.fecha_medicion
      FROM latest_results lr
      WHERE lr.rn = 1
    `
    
    const resultsResult = await pool.query(resultsQuery, [allMesaIds, inspectionId])
    
    // Group components by mesa and results by mesa
    const componentsByMesa = {}
    const resultsByMesa = {}
    
    componentsResult.rows.forEach(comp => {
      if (!componentsByMesa[comp.id_mesa]) componentsByMesa[comp.id_mesa] = []
      componentsByMesa[comp.id_mesa].push(comp)
    })
    
    resultsResult.rows.forEach(result => {
      if (!resultsByMesa[result.id_mesa]) resultsByMesa[result.id_mesa] = []
      resultsByMesa[result.id_mesa].push(result)
    })
    
    console.log(`[PDF-DATA] Loaded ${componentsResult.rows.length} components from ${Object.keys(componentsByMesa).length} mesas`)
    console.log(`[PDF-DATA] Loaded ${resultsResult.rows.length} results from ${allMesaIds.length} mesas`)
    
    // Build final mesa data structure
    const mesasWithData = mesas.map(mesa => {
      const components = componentsByMesa[mesa.id_mesa] || []
      const results = resultsByMesa[mesa.id_mesa] || []
      
      console.log(`[PDF-DATA] Mesa ${mesa.id_mesa}: ${components.length} components, ${results.length} results`)
      
      return {
        ...mesa,
        components,
        results
      }
    })
    
    return {
      inspection,
      mesas: mesasWithData,
      tiposEnsayo,
      colorRules,
      generated_at: new Date().toISOString()
    }
    
  } catch (error) {
    console.error('Error generating report data:', error)
    return null
  }
}

// Start the server
const port = process.env.PORT ? parseInt(process.env.PORT) : 8787

serve({
  fetch: app.fetch,
  port,
})

console.log(`🚀 Server running on http://localhost:${port}`)
