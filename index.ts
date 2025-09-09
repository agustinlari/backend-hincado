import 'dotenv/config'
import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { Pool } from 'pg'
import { serve } from '@hono/node-server'
import { jwt, sign, verify } from 'hono/jwt'
import * as jose from 'jose'
import puppeteer from 'puppeteer'
import ExcelJS from 'exceljs'
import { PDFDocument } from 'pdf-lib'
import * as fs from 'fs'
import * as path from 'path'

const app = new Hono()

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production'

// Configure CORS
app.use('/*', cors({
  origin: ['http://localhost:5173', 'http://localhost:3000', 'http://localhost:8789', 'https://aplicaciones.osmos.es:4444'],
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowHeaders: ['Content-Type', 'Authorization'],
}))

// Database connection
const pool = new Pool({
  user: process.env.DB_USER || 'postgres',
  host: process.env.DB_HOST || 'localhost',
  database: process.env.DB_NAME || 'fvinspeccioneshincas',
  password: process.env.DB_PASSWORD || 'Osmos2017',
  port: parseInt(process.env.DB_PORT || '5432'),
})

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

// Auth endpoints
app.post('/api/auth/login', async (c) => {
  try {
    const { username, password } = await c.req.json()
    
    if (!username || !password) {
      return c.json({ error: 'Username and password are required' }, 400)
    }

    const keycloakUrl = process.env.KEYCLOAK_INTERNAL_URL || 'http://127.0.0.1:8080'
    const realm = process.env.KEYCLOAK_REALM || 'master'
    const clientId = process.env.KEYCLOAK_CLIENT_ID || 'fotovoltaica-client'
    
    console.log('🔐 Iniciando login para:', username);
    console.log('🔗 URL interna:', keycloakUrl);
    console.log('🆔 Client ID:', clientId);
    
    // Obtener token de Keycloak usando URL interna
    const tokenUrl = `${keycloakUrl}/realms/${realm}/protocol/openid-connect/token`
    const requestBody = new URLSearchParams({
      grant_type: 'password',
      client_id: clientId,
      username: username,
      password: password,
    })

    console.log('📡 URL completa:', tokenUrl);

    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: requestBody,
    });

    console.log('📡 Status de respuesta:', response.status);

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      console.error('❌ Error de Keycloak:', errorData);
      return c.json({ 
        error: errorData.error_description || 'Credenciales inválidas' 
      }, 401);
    }

    const tokenData = await response.json();

    // Validar y decodificar el token
    const keycloakUser = await validateKeycloakToken(tokenData.access_token);

    return c.json({
      success: true,
      access_token: tokenData.access_token,
      refresh_token: tokenData.refresh_token,
      expires_in: tokenData.expires_in,
      user: {
        sub: keycloakUser.sub,
        email: keycloakUser.email,
        name: keycloakUser.name || keycloakUser.preferred_username,
        preferred_username: keycloakUser.preferred_username
      }
    });

  } catch (error: any) {
    console.error('❌ Error completo:', error);
    return c.json({ 
      error: error.message || 'Error de autenticación' 
    }, 401);
  }
})

app.get('/api/auth/callback', async (c) => {
  const code = c.req.query('code')
  
  if (!code) {
    return c.json({ error: 'Authorization code not provided' }, 400)
  }
  
  try {
    const keycloakUrl = process.env.KEYCLOAK_BASE_URL || 'https://aplicaciones.osmos.es:4444'
    const realm = process.env.KEYCLOAK_REALM || 'master'
    const clientId = process.env.KEYCLOAK_CLIENT_ID || 'fotovoltaica-client'
    const redirectUri = `${c.req.url.split('/api')[0]}/api/auth/callback`
    
    // Exchange code for tokens
    const tokenResponse = await fetch(`${keycloakUrl}/realms/${realm}/protocol/openid-connect/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: clientId,
        code,
        redirect_uri: redirectUri
      })
    })
    
    if (!tokenResponse.ok) {
      throw new Error('Failed to exchange code for tokens')
    }
    
    const tokens = await tokenResponse.json()
    
    // Get user info
    const userInfoResponse = await fetch(`${keycloakUrl}/realms/${realm}/protocol/openid-connect/userinfo`, {
      headers: {
        'Authorization': `Bearer ${tokens.access_token}`
      }
    })
    
    if (!userInfoResponse.ok) {
      throw new Error('Failed to get user info')
    }
    
    const userInfo = await userInfoResponse.json()
    
    // Create our own JWT token with user info
    const payload = {
      sub: userInfo.sub,
      email: userInfo.email,
      name: userInfo.name,
      preferred_username: userInfo.preferred_username,
      exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60) // 24 hours
    }
    
    const token = await sign(payload, JWT_SECRET)
    
    // Redirect to frontend with token
    return c.redirect(`/?token=${token}`)
    
  } catch (error) {
    console.error('Auth callback error:', error)
    return c.json({ error: 'Authentication failed' }, 500)
  }
})

app.post('/api/auth/verify', async (c) => {
  const authHeader = c.req.header('Authorization')
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return c.json({ error: 'No token provided' }, 401)
  }
  
  const token = authHeader.slice(7)
  
  try {
    // Validar token directamente con Keycloak
    const keycloakUser = await validateKeycloakToken(token);
    
    return c.json({
      user: {
        sub: keycloakUser.sub,
        email: keycloakUser.email,
        name: keycloakUser.name || keycloakUser.preferred_username,
        preferred_username: keycloakUser.preferred_username
      },
      valid: true
    })
  } catch (error: any) {
    console.error('Token verification failed:', error.message);
    return c.json({ error: 'Invalid token', valid: false }, 401)
  }
})

app.post('/api/auth/logout', (c) => {
  const keycloakUrl = process.env.KEYCLOAK_BASE_URL || 'https://aplicaciones.osmos.es:4444'
  const realm = process.env.KEYCLOAK_REALM || 'master'
  
  // Get the current origin to redirect back to login
  const host = c.req.header('host') || 'aplicaciones.osmos.es:4444'
  const protocol = host.includes('localhost') ? 'http' : 'https'
  
  console.log(`🔧 DEBUG - host: ${host}`);
  console.log(`🔧 DEBUG - keycloakUrl from env: ${process.env.KEYCLOAK_BASE_URL}`);
  console.log(`🔧 DEBUG - keycloakUrl final: ${keycloakUrl}`);
  
  // Construct the correct redirect URI for the login page
  let redirectUri;
  if (host.includes('localhost')) {
    // Development environment - redirect to local app
    redirectUri = `${protocol}://${host}/`
  } else {
    // Production environment - redirect back to the fvhincado app
    // Try with just the base URL in case the client allows wildcards
    redirectUri = 'https://aplicaciones.osmos.es:4444/fvhincado'
    
    console.log(`🔧 DEBUG - Redirect URI: ${redirectUri}`);
  }
  
  // Fix: Keycloak is served under /auth/ according to nginx config
  const logoutUrl = `${keycloakUrl}/auth/realms/${realm}/protocol/openid-connect/logout?redirect_uri=${encodeURIComponent(redirectUri)}`
  
  console.log(`🚪 Logout URL generada: ${logoutUrl}`);
  console.log(`🔄 Redirect URI: ${redirectUri}`);
  
  return c.json({ logoutUrl })
})

// Middleware for protected routes
const authMiddleware = async (c: any, next: any) => {
  console.log(`🔐 Auth middleware called for: ${c.req.method} ${c.req.url}`);
  
  // Skip auth in development mode if enabled
  if (process.env.ENABLE_DEV_AUTH === 'true') {
    c.set('user', { sub: '1', email: 'dev@example.com', name: 'Dev User' })
    return next()
  }
  
  const authHeader = c.req.header('Authorization')
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.error('❌ No authorization header found');
    return c.json({ error: 'Authentication required' }, 401)
  }
  
  const token = authHeader.slice(7)
  
  try {
    // Usar validateKeycloakToken en lugar de verify interno
    const keycloakUser = await validateKeycloakToken(token);
    c.set('user', {
      sub: keycloakUser.sub,
      email: keycloakUser.email,
      name: keycloakUser.name || keycloakUser.preferred_username,
      preferred_username: keycloakUser.preferred_username
    })
    console.log(`✅ Auth successful for: ${c.req.method} ${c.req.url}`);
    return next()
  } catch (error: any) {
    console.error(`❌ Auth failed for ${c.req.method} ${c.req.url}:`, error.message);
    return c.json({ error: 'Invalid token' }, 401)
  }
}

// Middleware para endpoints de exportación - soporta tanto Bearer token como API Key
const exportAuthMiddleware = async (c: any, next: any) => {
  console.log(`🔐 Export auth middleware called for: ${c.req.method} ${c.req.url}`);
  
  // Skip auth in development mode if enabled
  if (process.env.ENABLE_DEV_AUTH === 'true') {
    c.set('user', { sub: '1', email: 'dev@example.com', name: 'Dev User' })
    return next()
  }

  // Check for API Key first (for Power Query)
  const apiKey = c.req.header('x-api-key')
  if (apiKey) {
    const validApiKey = process.env.API_KEY || 'kE7pZ2nQ9xR4sWbV1yU8vA3mF6jH1gC4' // Default key para development
    if (apiKey === validApiKey) {
      c.set('user', { sub: 'api-key-user', email: 'api@system.com', name: 'API Key User' })
      console.log(`✅ API Key auth successful for: ${c.req.method} ${c.req.url}`);
      return next()
    } else {
      console.error('❌ Invalid API Key');
      return c.json({ error: 'Invalid API Key' }, 401)
    }
  }
  
  // Fallback to Bearer token authentication
  const authHeader = c.req.header('Authorization')
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.error('❌ No authorization header or API key found');
    return c.json({ error: 'Authentication required - provide Bearer token or x-api-key header' }, 401)
  }
  
  const token = authHeader.slice(7)
  
  try {
    const keycloakUser = await validateKeycloakToken(token);
    c.set('user', {
      sub: keycloakUser.sub,
      email: keycloakUser.email,
      name: keycloakUser.name || keycloakUser.preferred_username,
      preferred_username: keycloakUser.preferred_username
    })
    console.log(`✅ Bearer token auth successful for: ${c.req.method} ${c.req.url}`);
    return next()
  } catch (error: any) {
    console.error(`❌ Auth failed for ${c.req.method} ${c.req.url}:`, error.message);
    return c.json({ error: 'Invalid token' }, 401)
  }
}

// ================================
// EXPORT ENDPOINTS FOR POWER QUERY (must come before other endpoints)
// ================================

// Export inspecciones table
app.get('/api/export/inspecciones', exportAuthMiddleware, async (c) => {
  try {
    const result = await pool.query(`
      SELECT * FROM inspecciones 
      ORDER BY fecha_inicio DESC
    `)
    return c.json(result.rows)
  } catch (error) {
    console.error('Error exporting inspecciones:', error)
    return c.json({ 
      error: 'Failed to export inspecciones',
      details: error.message 
    }, 500)
  }
})

// Export inspecciones table (alternative endpoint to avoid route conflicts)
app.get('/api/export/inspecciones-data', exportAuthMiddleware, async (c) => {
  try {
    const result = await pool.query(`
      SELECT * FROM inspecciones 
      ORDER BY fecha_inicio DESC
    `)
    return c.json(result.rows)
  } catch (error) {
    console.error('Error exporting inspecciones data:', error)
    return c.json({ 
      error: 'Failed to export inspecciones data',
      details: error.message 
    }, 500)
  }
})

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

// Get all mesas with their CT and plantilla info
app.get('/api/mesas', authMiddleware, async (c) => {
  try {
    const query = `
      SELECT 
        m.id_mesa,
        m.nombre_mesa,
        m.coord_x,
        m.coord_y,
        ct.nombre_ct,
        mp.nombre_plantilla,
        mp.dimension_x,
        mp.dimension_y
      FROM mesas m
      JOIN cts ct ON m.id_ct = ct.id_ct
      JOIN mesa_plantillas mp ON m.id_plantilla = mp.id_plantilla
      WHERE m.coord_x IS NOT NULL AND m.coord_y IS NOT NULL
      ORDER BY m.id_mesa
    `
    const result = await pool.query(query)
    return c.json(result.rows)
  } catch (error) {
    console.error('Error fetching mesas:', error)
    return c.json({ error: 'Failed to fetch mesas' }, 500)
  }
})

// Get mesa details by ID
app.get('/api/mesas/:id', authMiddleware, async (c) => {
  const id = c.req.param('id')
  try {
    const query = `
      SELECT 
        m.id_mesa,
        m.nombre_mesa,
        m.coord_x,
        m.coord_y,
        ct.nombre_ct,
        mp.nombre_plantilla,
        mp.descripcion as plantilla_descripcion,
        mp.dimension_x,
        mp.dimension_y
      FROM mesas m
      JOIN cts ct ON m.id_ct = ct.id_ct
      JOIN mesa_plantillas mp ON m.id_plantilla = mp.id_plantilla
      WHERE m.id_mesa = $1
    `
    const result = await pool.query(query, [id])
    
    if (result.rows.length === 0) {
      return c.json({ error: 'Mesa not found' }, 404)
    }
    
    return c.json(result.rows[0])
  } catch (error) {
    console.error('Error fetching mesa:', error)
    return c.json({ error: 'Failed to fetch mesa' }, 500)
  }
})

// Get components for a mesa
app.get('/api/mesas/:id/components', authMiddleware, async (c) => {
  const id = c.req.param('id')
  console.log(`🔍 GET /api/mesas/${id}/components called`)
  try {
    const query = `
      SELECT 
        pc.id_componente,
        pc.tipo_elemento,
        pc.coord_x,
        pc.coord_y,
        pc.descripcion_punto_montaje,
        pc.orden_prioridad
      FROM mesas m
      JOIN plantilla_componentes pc ON m.id_plantilla = pc.id_plantilla
      WHERE m.id_mesa = $1
      ORDER BY pc.orden_prioridad ASC, pc.tipo_elemento, pc.coord_x, pc.coord_y
    `
    const result = await pool.query(query, [id])
    console.log(`✅ Found ${result.rows.length} components for mesa ${id}`)
    return c.json(result.rows)
  } catch (error) {
    console.error('Error fetching mesa components:', error)
    return c.json({ error: 'Failed to fetch mesa components' }, 500)
  }
})

// Get full mesa data for printing reports
app.get('/api/mesas/:id/full-report-data/:inspectionId', authMiddleware, async (c) => {
  const mesaId = c.req.param('id')
  const inspectionId = c.req.param('inspectionId')
  
  try {
    // Get mesa basic info
    const mesaQuery = `
      SELECT 
        m.id_mesa,
        m.nombre_mesa,
        m.coord_x,
        m.coord_y,
        c.nombre_ct,
        mp.nombre_plantilla,
        mp.dimension_x,
        mp.dimension_y,
        mp.id_plantilla
      FROM mesas m
      JOIN cts c ON m.id_ct = c.id_ct
      JOIN mesa_plantillas mp ON m.id_plantilla = mp.id_plantilla
      WHERE m.id_mesa = $1
    `
    
    const mesaResult = await pool.query(mesaQuery, [mesaId])
    if (mesaResult.rows.length === 0) {
      return c.json({ error: 'Mesa not found' }, 404)
    }
    
    const mesa = mesaResult.rows[0]
    
    // Get plantilla components
    const componentsQuery = `
      SELECT 
        id_componente,
        tipo_elemento,
        coord_x,
        coord_y,
        descripcion_punto_montaje,
        orden_prioridad
      FROM plantilla_componentes 
      WHERE id_plantilla = $1
      ORDER BY orden_prioridad ASC, tipo_elemento, coord_x, coord_y
    `
    
    const componentsResult = await pool.query(componentsQuery, [mesa.id_plantilla])
    
    // Get all tipos ensayo
    const tiposEnsayoQuery = `
      SELECT 
        id_tipo_ensayo,
        nombre_ensayo,
        descripcion,
        unidad_medida,
        grupo_ensayo,
        tipo_resultado,
        minimo_admisible,
        maximo_admisible,
        orden_prioridad
      FROM tipos_ensayo
      ORDER BY grupo_ensayo, orden_prioridad ASC, nombre_ensayo
    `
    
    const tiposEnsayoResult = await pool.query(tiposEnsayoQuery)
    
    // Get test results for this mesa and inspection
    const resultsQuery = `
      SELECT 
        re.id_tipo_ensayo,
        re.id_componente_plantilla_1,
        re.resultado_numerico,
        re.resultado_booleano,
        re.resultado_texto,
        re.comentario,
        re.fecha_medicion
      FROM resultados_ensayos re
      WHERE re.id_mesa = $1 AND re.id_inspeccion = $2
    `
    
    const resultsResult = await pool.query(resultsQuery, [mesaId, inspectionId])
    
    return c.json({
      ...mesa,
      components: componentsResult.rows,
      tiposEnsayo: tiposEnsayoResult.rows,
      results: resultsResult.rows
    })
    
  } catch (error) {
    console.error('Error fetching mesa full report data:', error)
    return c.json({ error: 'Failed to fetch mesa report data' }, 500)
  }
})

// Recalculate mesa dimensions based on components
app.post('/api/recalculate-dimensions', async (c) => {
  try {
    // Calculate dimensions for each plantilla based on component coordinates
    const updateQuery = `
      UPDATE mesa_plantillas 
      SET 
          dimension_x = GREATEST(
              COALESCE(
                  CASE 
                      WHEN componentes.num_paneles > 0 THEN
                          -- Component coords are in mm, add 1000mm (1m) margin for panels
                          (componentes.max_x - componentes.min_x) + 1000.0
                      ELSE
                          -- Add 400mm (0.4m) margin for mounting points
                          (componentes.max_x - componentes.min_x) + 400.0
                  END, 
                  20000.0  -- Default 20m in mm
              ), 
              1000.0  -- Minimum 1m in mm
          ),
          dimension_y = GREATEST(
              COALESCE(
                  CASE 
                      WHEN componentes.num_paneles > 0 THEN
                          -- Component coords are in mm, add 1000mm (1m) margin for panels
                          (componentes.max_y - componentes.min_y) + 1000.0
                      ELSE
                          -- Add 400mm (0.4m) margin for mounting points
                          (componentes.max_y - componentes.min_y) + 400.0
                  END, 
                  6000.0   -- Default 6m in mm
              ), 
              1000.0   -- Minimum 1m in mm
          )
      FROM (
          SELECT 
              id_plantilla,
              MAX(coord_x) as max_x,
              MIN(coord_x) as min_x,
              MAX(coord_y) as max_y,
              MIN(coord_y) as min_y,
              COUNT(CASE WHEN tipo_elemento = 'PANEL' THEN 1 END) as num_paneles
          FROM plantilla_componentes
          GROUP BY id_plantilla
      ) as componentes
      WHERE mesa_plantillas.id_plantilla = componentes.id_plantilla
    `;
    
    const result = await pool.query(updateQuery);
    
    // Set default dimensions for plantillas without components
    const defaultQuery = `
      UPDATE mesa_plantillas 
      SET 
          dimension_x = 20000.0,  -- 20m in mm
          dimension_y = 6000.0    -- 6m in mm
      WHERE id_plantilla NOT IN (
          SELECT DISTINCT id_plantilla 
          FROM plantilla_componentes
      )
    `;
    
    await pool.query(defaultQuery);
    
    // Get summary of changes
    const summaryQuery = `
      SELECT 
          mp.id_plantilla,
          mp.nombre_plantilla,
          ROUND((mp.dimension_x / 1000.0)::numeric, 2) as dimension_x_meters,
          ROUND((mp.dimension_y / 1000.0)::numeric, 2) as dimension_y_meters,
          COALESCE(comp_stats.total_componentes, 0) as total_componentes,
          COALESCE(comp_stats.num_paneles, 0) as num_paneles,
          COALESCE(comp_stats.num_puntos_montaje, 0) as num_puntos_montaje
      FROM mesa_plantillas mp
      LEFT JOIN (
          SELECT 
              id_plantilla,
              COUNT(*) as total_componentes,
              COUNT(CASE WHEN tipo_elemento = 'PANEL' THEN 1 END) as num_paneles,
              COUNT(CASE WHEN tipo_elemento = 'PUNTO_MONTAJE' THEN 1 END) as num_puntos_montaje
          FROM plantilla_componentes
          GROUP BY id_plantilla
      ) comp_stats ON mp.id_plantilla = comp_stats.id_plantilla
      ORDER BY mp.nombre_plantilla
    `;
    
    const summary = await pool.query(summaryQuery);
    
    return c.json({ 
      message: 'Dimensions recalculated successfully',
      updated_plantillas: result.rowCount,
      plantillas: summary.rows
    });
    
  } catch (error) {
    console.error('Error recalculating dimensions:', error);
    return c.json({ error: 'Failed to recalculate dimensions' }, 500);
  }
});

// ==================== TIPOS DE ENSAYO ====================

// Get all tipos de ensayo
app.get('/api/tipos-ensayo', authMiddleware, async (c) => {
  try {
    const query = `
      SELECT 
        id_tipo_ensayo,
        nombre_ensayo,
        descripcion,
        unidad_medida,
        grupo_ensayo,
        tipo_resultado,
        minimo_admisible,
        maximo_admisible,
        orden_prioridad
      FROM tipos_ensayo
      ORDER BY orden_prioridad ASC, grupo_ensayo, nombre_ensayo
    `
    const result = await pool.query(query)
    return c.json(result.rows)
  } catch (error) {
    console.error('Error fetching tipos de ensayo:', error)
    return c.json({ error: 'Failed to fetch tipos de ensayo' }, 500)
  }
})

// Create tipo de ensayo
app.post('/api/tipos-ensayo', authMiddleware, async (c) => {
  try {
    const body = await c.req.json()
    const { 
      nombre_ensayo, 
      descripcion, 
      unidad_medida, 
      grupo_ensayo, 
      tipo_resultado, 
      minimo_admisible, 
      maximo_admisible 
    } = body
    
    if (!nombre_ensayo || !tipo_resultado) {
      return c.json({ error: 'Missing required fields: nombre_ensayo, tipo_resultado' }, 400)
    }
    
    const query = `
      INSERT INTO tipos_ensayo (
        nombre_ensayo, descripcion, unidad_medida, grupo_ensayo, 
        tipo_resultado, minimo_admisible, maximo_admisible
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING *
    `
    
    const result = await pool.query(query, [
      nombre_ensayo, descripcion, unidad_medida, grupo_ensayo,
      tipo_resultado, minimo_admisible, maximo_admisible
    ])
    
    return c.json(result.rows[0])
  } catch (error) {
    console.error('Error creating tipo de ensayo:', error)
    return c.json({ error: 'Failed to create tipo de ensayo' }, 500)
  }
})

// ==================== REGLAS DE COLORES PARA RESULTADOS ====================

// Get all color rules for test results
app.get('/api/reglas-resultados-ensayos', authMiddleware, async (c) => {
  try {
    const query = `
      SELECT 
        r.id,
        r.id_tipo_ensayo,
        r.tipo_condicion,
        r.valor_numerico_1,
        r.valor_numerico_2,
        r.valor_booleano,
        r.valor_texto,
        r.resaltado,
        r.comentario,
        r.prioridad,
        te.nombre_ensayo,
        te.tipo_resultado
      FROM reglas_resultados_ensayos r
      JOIN tipos_ensayo te ON r.id_tipo_ensayo = te.id_tipo_ensayo
      ORDER BY r.id_tipo_ensayo, r.prioridad DESC, r.id
    `
    const result = await pool.query(query)
    return c.json(result.rows)
  } catch (error) {
    console.error('Error fetching color rules:', error)
    return c.json({ error: 'Failed to fetch color rules' }, 500)
  }
})

// Create color rule
app.post('/api/reglas-resultados-ensayos', authMiddleware, async (c) => {
  try {
    const body = await c.req.json()
    const { 
      id_tipo_ensayo,
      tipo_condicion,
      valor_numerico_1,
      valor_numerico_2,
      valor_booleano,
      valor_texto,
      resaltado,
      comentario,
      prioridad = 0
    } = body
    
    if (!id_tipo_ensayo || !tipo_condicion) {
      return c.json({ error: 'Missing required fields: id_tipo_ensayo, tipo_condicion' }, 400)
    }
    
    // Validate tipo_condicion
    const validConditions = ['=', '<>', '>', '<', '>=', '<=', 'ENTRE', 'FUERA_DE']
    if (!validConditions.includes(tipo_condicion)) {
      return c.json({ error: 'Invalid tipo_condicion. Must be one of: ' + validConditions.join(', ') }, 400)
    }
    
    const query = `
      INSERT INTO reglas_resultados_ensayos (
        id_tipo_ensayo, tipo_condicion, valor_numerico_1, valor_numerico_2,
        valor_booleano, valor_texto, resaltado, comentario, prioridad
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      RETURNING *
    `
    
    const result = await pool.query(query, [
      id_tipo_ensayo, tipo_condicion, valor_numerico_1, valor_numerico_2,
      valor_booleano, valor_texto, resaltado, comentario, prioridad
    ])
    
    return c.json({
      success: true,
      regla: result.rows[0],
      message: 'Regla de color creada exitosamente'
    })
  } catch (error) {
    console.error('Error creating color rule:', error)
    return c.json({ error: 'Failed to create color rule' }, 500)
  }
})

// Update color rule
app.put('/api/reglas-resultados-ensayos/:id', authMiddleware, async (c) => {
  try {
    const id = c.req.param('id')
    const body = await c.req.json()
    const { 
      id_tipo_ensayo,
      tipo_condicion,
      valor_numerico_1,
      valor_numerico_2,
      valor_booleano,
      valor_texto,
      resaltado,
      comentario,
      prioridad
    } = body
    
    // Validate tipo_condicion if provided
    if (tipo_condicion) {
      const validConditions = ['=', '<>', '>', '<', '>=', '<=', 'ENTRE', 'FUERA_DE']
      if (!validConditions.includes(tipo_condicion)) {
        return c.json({ error: 'Invalid tipo_condicion. Must be one of: ' + validConditions.join(', ') }, 400)
      }
    }
    
    const query = `
      UPDATE reglas_resultados_ensayos 
      SET 
        id_tipo_ensayo = COALESCE($1, id_tipo_ensayo),
        tipo_condicion = COALESCE($2, tipo_condicion),
        valor_numerico_1 = COALESCE($3, valor_numerico_1),
        valor_numerico_2 = COALESCE($4, valor_numerico_2),
        valor_booleano = COALESCE($5, valor_booleano),
        valor_texto = COALESCE($6, valor_texto),
        resaltado = COALESCE($7, resaltado),
        comentario = COALESCE($8, comentario),
        prioridad = COALESCE($9, prioridad)
      WHERE id = $10
      RETURNING *
    `
    
    const result = await pool.query(query, [
      id_tipo_ensayo, tipo_condicion, valor_numerico_1, valor_numerico_2,
      valor_booleano, valor_texto, resaltado, comentario, prioridad, id
    ])
    
    if (result.rows.length === 0) {
      return c.json({ error: 'Color rule not found' }, 404)
    }
    
    return c.json({
      success: true,
      regla: result.rows[0],
      message: 'Regla de color actualizada exitosamente'
    })
  } catch (error) {
    console.error('Error updating color rule:', error)
    return c.json({ error: 'Failed to update color rule' }, 500)
  }
})

// Delete color rule
app.delete('/api/reglas-resultados-ensayos/:id', authMiddleware, async (c) => {
  try {
    const id = c.req.param('id')
    
    const query = `
      DELETE FROM reglas_resultados_ensayos 
      WHERE id = $1
      RETURNING id
    `
    
    const result = await pool.query(query, [id])
    
    if (result.rows.length === 0) {
      return c.json({ error: 'Color rule not found' }, 404)
    }
    
    return c.json({
      success: true,
      message: 'Regla de color eliminada exitosamente'
    })
  } catch (error) {
    console.error('Error deleting color rule:', error)
    return c.json({ error: 'Failed to delete color rule' }, 500)
  }
})

// ==================== INSPECCIONES ====================

// Create a new inspection session
app.post('/api/inspecciones', authMiddleware, async (c) => {
  try {
    const body = await c.req.json()
    const { descripcion } = body
    
    // Get user ID from auth token
    const user = c.get('user')
    
    // Extract user ID from the JWT token (sub field contains the user ID)
    // For now, we'll use a hash of the sub to create a consistent integer ID
    const id_usuario = user?.sub ? Math.abs(user.sub.split('').reduce((hash, char) => {
      return ((hash << 5) - hash + char.charCodeAt(0)) & 0xffffffff;
    }, 0)) : 1
    
    console.log('👤 Creando inspección para usuario:', { id_usuario, userSub: user?.sub, username: user?.preferred_username });
    
    // Store user info in cache for future lookups
    if (user?.sub) {
      storeUserInfo(user.sub, id_usuario, {
        name: user.name,
        preferred_username: user.preferred_username
      });
    }
    
    const query = `
      INSERT INTO inspecciones (id_usuario, descripcion, estado)
      VALUES ($1, $2, 'EN_PROCESO')
      RETURNING *
    `
    
    const result = await pool.query(query, [id_usuario, descripcion || null])
    
    return c.json({
      success: true,
      inspeccion: result.rows[0],
      message: 'Inspección creada exitosamente'
    })
  } catch (error) {
    console.error('Error creating inspection:', error)
    return c.json({ error: 'Failed to create inspection' }, 500)
  }
})

// Update inspection status
app.patch('/api/inspecciones/:id', authMiddleware, async (c) => {
  try {
    const id_inspeccion = c.req.param('id')
    const body = await c.req.json()
    const { estado, descripcion, fecha_fin } = body
    
    const query = `
      UPDATE inspecciones 
      SET 
        estado = COALESCE($1, estado),
        descripcion = COALESCE($2, descripcion),
        fecha_fin = COALESCE($3, fecha_fin)
      WHERE id_inspeccion = $4
      RETURNING *
    `
    
    const result = await pool.query(query, [estado, descripcion, fecha_fin, id_inspeccion])
    
    if (result.rows.length === 0) {
      return c.json({ error: 'Inspection not found' }, 404)
    }
    
    return c.json({
      success: true,
      inspeccion: result.rows[0],
      message: 'Inspección actualizada exitosamente'
    })
  } catch (error) {
    console.error('Error updating inspection:', error)
    return c.json({ error: 'Failed to update inspection' }, 500)
  }
})


// Get all inspections
app.get('/api/inspecciones', authMiddleware, async (c) => {
  try {
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
    `
    const result = await pool.query(query)
    return c.json(result.rows)
  } catch (error) {
    console.error('Error fetching inspections:', error)
    return c.json({ error: 'Failed to fetch inspections' }, 500)
  }
})

// Test endpoint for DELETE method
app.delete('/api/test-delete/:id', async (c) => {
  return c.json({ success: true, message: 'DELETE test successful', id: c.req.param('id') })
})

// Delete inspection
app.delete('/api/inspecciones/:id', authMiddleware, async (c) => {
  console.log('🗑️ DELETE /api/inspecciones/:id called with id:', c.req.param('id'))
  try {
    const id_inspeccion = c.req.param('id')
    
    const query = `
      DELETE FROM inspecciones 
      WHERE id_inspeccion = $1
      RETURNING id_inspeccion
    `
    
    const result = await pool.query(query, [id_inspeccion])
    
    if (result.rows.length === 0) {
      return c.json({ error: 'Inspection not found' }, 404)
    }
    
    return c.json({
      success: true,
      message: 'Inspección eliminada exitosamente'
    })
  } catch (error) {
    console.error('Error deleting inspection:', error)
    return c.json({ error: 'Failed to delete inspection' }, 500)
  }
})

// User cache to store user information
// Maps both UUID (from JWT) and integer ID (from DB) to user info
const userCache = new Map<string, { name?: string, preferred_username?: string, userId?: number, uuid?: string }>();
const idToUuidCache = new Map<number, string>(); // Maps integer ID back to UUID

// Function to get or fetch user info by integer ID
async function getUserInfo(userId: string): Promise<{ name?: string, preferred_username?: string }> {
  const numericUserId = parseInt(userId);
  
  // First check if we have UUID mapping for this numeric ID
  const uuid = idToUuidCache.get(numericUserId);
  if (uuid && userCache.has(uuid)) {
    return userCache.get(uuid)!;
  }
  
  // Check cache by string ID directly
  if (userCache.has(userId)) {
    return userCache.get(userId)!;
  }
  
  // For now, return a placeholder. In a real implementation, you would:
  // 1. Query a local users table, or
  // 2. Make a call to Keycloak Admin API to get user info, or
  // 3. Store user info when they first authenticate
  const userInfo = { name: `Usuario ${userId}`, preferred_username: `user${userId}` };
  userCache.set(userId, userInfo);
  return userInfo;
}

// Function to store user info and create mappings
function storeUserInfo(uuid: string, userId: number, userInfo: { name?: string, preferred_username?: string }) {
  // Store in cache with UUID as key
  userCache.set(uuid, { ...userInfo, userId, uuid });
  // Create reverse mapping from integer ID to UUID
  idToUuidCache.set(userId, uuid);
}

// Get all inspections (simplified for now - later filter by mesa through resultados_ensayos)
app.get('/api/mesas/:id/inspecciones', authMiddleware, async (c) => {
  try {
    const user = c.get('user');
    
    // Get query parameters for filtering
    const showAll = c.req.query('showAll') === 'true';
    const filterByUser = c.req.query('filterByUser') !== 'false'; // Default to true
    const filterByStatus = c.req.query('filterByStatus') !== 'false'; // Default to true
    
    // Store current user info in cache if available
    let currentUserId = 1;
    if (user?.sub) {
      currentUserId = Math.abs(user.sub.split('').reduce((hash, char) => {
        return ((hash << 5) - hash + char.charCodeAt(0)) & 0xffffffff;
      }, 0));
      
      storeUserInfo(user.sub, currentUserId, {
        name: user.name,
        preferred_username: user.preferred_username
      });
    }
    
    // Build query with conditional WHERE clause
    let query = `
      SELECT 
        id_inspeccion,
        fecha_inicio,
        fecha_fin,
        descripcion,
        estado,
        id_usuario
      FROM inspecciones
    `;
    
    const conditions = [];
    const params = [];
    let paramIndex = 1;
    
    // Apply filters if not showing all
    if (!showAll) {
      if (filterByUser) {
        conditions.push(`id_usuario = $${paramIndex}`);
        params.push(currentUserId);
        paramIndex++;
      }
      
      if (filterByStatus) {
        conditions.push(`estado = $${paramIndex}`);
        params.push('EN_PROCESO');
        paramIndex++;
      }
    }
    
    if (conditions.length > 0) {
      query += ` WHERE ${conditions.join(' AND ')}`;
    }
    
    query += ` ORDER BY fecha_inicio DESC`;
    
    console.log('🔍 Query inspecciones:', { query, params, showAll, currentUserId, userSub: user?.sub });
    
    const result = await pool.query(query, params)
    
    // Enrich inspections with user information
    const enrichedInspections = await Promise.all(result.rows.map(async (inspection) => {
      const userInfo = await getUserInfo(inspection.id_usuario.toString());
      return {
        ...inspection,
        usuario_nombre: userInfo.name,
        usuario_username: userInfo.preferred_username
      };
    }));
    
    return c.json(enrichedInspections)
  } catch (error) {
    console.error('Error fetching inspections:', error)
    return c.json({ error: 'Failed to fetch inspections' }, 500)
  }
})

// ==================== RESULTADOS DE ENSAYOS ====================

// Create resultado de ensayo
app.post('/api/resultados-ensayos', authMiddleware, async (c) => {
  try {
    const body = await c.req.json()
    const { 
      id_inspeccion, 
      id_tipo_ensayo, 
      id_mesa, 
      id_componente_plantilla_1, 
      id_componente_plantilla_2,
      resultado_numerico,
      resultado_booleano,
      resultado_texto,
      comentario
    } = body
    
    // Validate required fields
    if (!id_inspeccion || !id_tipo_ensayo || !id_mesa || !id_componente_plantilla_1) {
      return c.json({ 
        error: 'Missing required fields: id_inspeccion, id_tipo_ensayo, id_mesa, id_componente_plantilla_1' 
      }, 400)
    }
    
    const query = `
      INSERT INTO resultados_ensayos (
        id_inspeccion, id_tipo_ensayo, id_mesa, 
        id_componente_plantilla_1, id_componente_plantilla_2,
        resultado_numerico, resultado_booleano, resultado_texto, comentario
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      RETURNING *
    `
    
    const result = await pool.query(query, [
      id_inspeccion, id_tipo_ensayo, id_mesa,
      id_componente_plantilla_1, id_componente_plantilla_2,
      resultado_numerico, resultado_booleano, resultado_texto, comentario
    ])
    
    return c.json({
      success: true,
      resultado: result.rows[0],
      message: 'Resultado de ensayo guardado exitosamente'
    })
  } catch (error) {
    console.error('Error creating resultado ensayo:', error)
    return c.json({ error: 'Failed to create resultado ensayo' }, 500)
  }
})

// Get all components with mesa information
app.get('/api/components', authMiddleware, async (c) => {
  try {
    const query = `
      SELECT 
        pc.id_componente,
        pc.id_plantilla,
        pc.tipo_elemento,
        pc.coord_x,
        pc.coord_y,
        pc.descripcion_punto_montaje,
        mp.nombre_plantilla,
        mp.descripcion as plantilla_descripcion,
        mp.dimension_x as plantilla_dimension_x,
        mp.dimension_y as plantilla_dimension_y,
        m.id_mesa,
        m.nombre_mesa,
        m.coord_x as mesa_coord_x,
        m.coord_y as mesa_coord_y,
        ct.nombre_ct
      FROM plantilla_componentes pc
      JOIN mesa_plantillas mp ON pc.id_plantilla = mp.id_plantilla
      JOIN mesas m ON m.id_plantilla = mp.id_plantilla
      JOIN cts ct ON m.id_ct = ct.id_ct
      WHERE pc.tipo_elemento = 'PUNTO_MONTAJE'
      ORDER BY ct.nombre_ct, m.nombre_mesa, pc.orden_prioridad ASC, pc.id_componente
    `
    
    const result = await pool.query(query)
    return c.json(result.rows)
  } catch (error) {
    console.error('Error fetching components:', error)
    return c.json({ error: 'Failed to fetch components' }, 500)
  }
})

// Get latest test results for components
app.get('/api/components/test-results/latest', authMiddleware, async (c) => {
  try {
    // CORRECTED: Partition by mesa + component + test type to get results per specific component in specific mesa
    const query = `
      WITH latest_results AS (
        SELECT 
          re.*,
          ROW_NUMBER() OVER (
            PARTITION BY re.id_mesa, re.id_componente_plantilla_1, re.id_tipo_ensayo 
            ORDER BY re.fecha_medicion DESC, re.id_resultado DESC
          ) as rn
        FROM resultados_ensayos re
        INNER JOIN mesas m ON m.id_mesa = re.id_mesa
        INNER JOIN inspecciones i ON re.id_inspeccion = i.id_inspeccion
        WHERE re.id_componente_plantilla_1 IS NOT NULL
      )
      SELECT 
        -- Create a unique component identifier per mesa
        CONCAT(lr.id_mesa, '_', lr.id_componente_plantilla_1) as id_componente,
        lr.id_mesa,
        lr.id_componente_plantilla_1,
        lr.id_tipo_ensayo,
        lr.resultado_numerico,
        lr.resultado_booleano,
        lr.resultado_texto,
        lr.comentario,
        lr.fecha_medicion,
        te.nombre_ensayo,
        te.tipo_resultado,
        te.unidad_medida
      FROM latest_results lr
      INNER JOIN tipos_ensayo te ON lr.id_tipo_ensayo = te.id_tipo_ensayo
      WHERE lr.rn = 1
      ORDER BY lr.id_mesa, lr.id_componente_plantilla_1, te.orden_prioridad ASC, te.grupo_ensayo, te.nombre_ensayo
    `
    
    const result = await pool.query(query)
    return c.json(result.rows)
  } catch (error) {
    console.error('Error fetching component test results:', error)
    return c.json({ error: 'Failed to fetch component test results' }, 500)
  }
})

// Get latest test results for a specific mesa
app.get('/api/mesas/:id/test-results/latest', authMiddleware, async (c) => {
  const mesaId = c.req.param('id')
  try {
    // Optimized query - only get results for the specific mesa
    const query = `
      WITH latest_results AS (
        SELECT 
          re.*,
          ROW_NUMBER() OVER (
            PARTITION BY re.id_componente_plantilla_1, re.id_tipo_ensayo 
            ORDER BY re.fecha_medicion DESC, re.id_resultado DESC
          ) as rn
        FROM resultados_ensayos re
        INNER JOIN inspecciones i ON re.id_inspeccion = i.id_inspeccion
        WHERE re.id_mesa = $1 AND re.id_componente_plantilla_1 IS NOT NULL
      )
      SELECT 
        -- Create a unique component identifier per mesa
        CONCAT(lr.id_mesa, '_', lr.id_componente_plantilla_1) as id_componente,
        lr.id_mesa,
        lr.id_componente_plantilla_1,
        lr.id_tipo_ensayo,
        lr.resultado_numerico,
        lr.resultado_booleano,
        lr.resultado_texto,
        lr.comentario,
        lr.fecha_medicion,
        te.nombre_ensayo,
        te.tipo_resultado,
        te.unidad_medida
      FROM latest_results lr
      INNER JOIN tipos_ensayo te ON lr.id_tipo_ensayo = te.id_tipo_ensayo
      WHERE lr.rn = 1
      ORDER BY lr.id_componente_plantilla_1, te.orden_prioridad ASC, te.grupo_ensayo, te.nombre_ensayo
    `
    
    const result = await pool.query(query, [mesaId])
    return c.json(result.rows)
  } catch (error) {
    console.error('Error fetching mesa test results:', error)
    return c.json({ error: 'Failed to fetch mesa test results' }, 500)
  }
})

// Get latest test results for all mesas and test types
// Debug endpoint to check resultados_ensayos raw data
app.get('/api/resultados-ensayos/debug', authMiddleware, async (c) => {
  try {
    const query = `
      SELECT 
        re.id_resultado,
        re.id_mesa,
        re.id_tipo_ensayo,
        re.resultado_numerico,
        re.resultado_booleano,
        re.resultado_texto,
        re.fecha_medicion,
        te.nombre_ensayo,
        m.nombre_mesa
      FROM resultados_ensayos re
      JOIN tipos_ensayo te ON re.id_tipo_ensayo = te.id_tipo_ensayo
      LEFT JOIN mesas m ON re.id_mesa = m.id_mesa
      ORDER BY re.id_mesa, te.nombre_ensayo, re.fecha_medicion DESC
    `
    
    const result = await pool.query(query)
    console.log('📊 Debug resultados_ensayos:')
    console.log('Total rows:', result.rows.length)
    
    // Group by tipo_ensayo to see distribution
    const byTipoEnsayo = result.rows.reduce((acc, row) => {
      const tipo = row.nombre_ensayo
      if (!acc[tipo]) acc[tipo] = []
      acc[tipo].push({
        id_mesa: row.id_mesa,
        nombre_mesa: row.nombre_mesa,
        fecha_medicion: row.fecha_medicion
      })
      return acc
    }, {})
    
    console.log('Distribution by tipo_ensayo:')
    Object.entries(byTipoEnsayo).forEach(([tipo, registros]) => {
      console.log(`  ${tipo}: ${registros.length} registros`)
      registros.slice(0, 3).forEach(r => {
        console.log(`    - Mesa ${r.id_mesa} (${r.nombre_mesa}) - ${r.fecha_medicion}`)
      })
    })
    
    return c.json({
      total_rows: result.rows.length,
      distribution: Object.fromEntries(
        Object.entries(byTipoEnsayo).map(([tipo, registros]) => [tipo, registros.length])
      ),
      sample_data: result.rows.slice(0, 10)
    })
  } catch (error) {
    console.error('Error in debug endpoint:', error)
    return c.json({ error: 'Debug query failed' }, 500)
  }
})

app.get('/api/resultados-ensayos/latest', authMiddleware, async (c) => {
  try {
    // Clean, simple query - only return results for the exact mesa they belong to
    const query = `
      WITH latest_results AS (
        SELECT 
          re.id_mesa,
          re.id_tipo_ensayo,
          re.resultado_numerico,
          re.resultado_booleano,
          re.resultado_texto,
          re.fecha_medicion,
          ROW_NUMBER() OVER (
            PARTITION BY re.id_mesa, re.id_tipo_ensayo 
            ORDER BY re.fecha_medicion DESC, re.id_resultado DESC
          ) as rn
        FROM resultados_ensayos re
        INNER JOIN mesas m ON m.id_mesa = re.id_mesa
        INNER JOIN inspecciones i ON re.id_inspeccion = i.id_inspeccion
      )
      SELECT 
        lr.id_mesa,
        lr.id_tipo_ensayo,
        lr.resultado_numerico,
        lr.resultado_booleano,
        lr.resultado_texto,
        lr.fecha_medicion,
        te.nombre_ensayo,
        te.tipo_resultado,
        te.unidad_medida
      FROM latest_results lr
      INNER JOIN tipos_ensayo te ON lr.id_tipo_ensayo = te.id_tipo_ensayo
      WHERE lr.rn = 1
      ORDER BY lr.id_mesa, te.orden_prioridad ASC, te.grupo_ensayo, te.nombre_ensayo
    `
    
    const result = await pool.query(query)
    return c.json(result.rows)
  } catch (error) {
    console.error('Error fetching latest test results:', error)
    return c.json({ error: 'Failed to fetch latest test results' }, 500)
  }
})

// Get resultados for an inspection
app.get('/api/inspecciones/:id/resultados', authMiddleware, async (c) => {
  const id_inspeccion = c.req.param('id')
  try {
    const query = `
      SELECT 
        re.*,
        te.nombre_ensayo,
        te.descripcion as ensayo_descripcion,
        te.tipo_resultado,
        te.unidad_medida,
        te.grupo_ensayo,
        m.nombre_mesa,
        pc1.tipo_elemento as componente1_tipo,
        pc1.descripcion_punto_montaje as componente1_descripcion,
        pc1.coord_x as componente1_x,
        pc1.coord_y as componente1_y,
        pc2.tipo_elemento as componente2_tipo,
        pc2.descripcion_punto_montaje as componente2_descripcion,
        pc2.coord_x as componente2_x,
        pc2.coord_y as componente2_y
      FROM resultados_ensayos re
      JOIN tipos_ensayo te ON re.id_tipo_ensayo = te.id_tipo_ensayo
      JOIN mesas m ON re.id_mesa = m.id_mesa
      JOIN plantilla_componentes pc1 ON re.id_componente_plantilla_1 = pc1.id_componente
      LEFT JOIN plantilla_componentes pc2 ON re.id_componente_plantilla_2 = pc2.id_componente
      WHERE re.id_inspeccion = $1
      ORDER BY re.fecha_medicion DESC
    `
    const result = await pool.query(query, [id_inspeccion])
    return c.json(result.rows)
  } catch (error) {
    console.error('Error fetching inspection results:', error)
    return c.json({ error: 'Failed to fetch inspection results' }, 500)
  }
})

// Dashboard statistics endpoint
app.get('/api/dashboard/estadisticas', authMiddleware, async (c) => {
  try {
    console.log('📊 Fetching real dashboard statistics...')
    
    // Get total number of tests
    const totalEnsayosQuery = 'SELECT COUNT(*) as total FROM resultados_ensayos'
    const totalEnsayosResult = await pool.query(totalEnsayosQuery)
    const totalEnsayos = parseInt(totalEnsayosResult.rows[0].total)
    
    // Get failed tests using comentario field (OK = correcto, NOK = fallido)
    const ensayosFallidosQuery = `
      SELECT 
        COUNT(CASE WHEN te.tipo_resultado = 'BOOLEANO' THEN 1 END) as total_booleanos,
        COUNT(CASE WHEN te.tipo_resultado = 'NUMERICO' THEN 1 END) as total_numericos,
        COUNT(CASE WHEN te.tipo_resultado = 'TEXTO' THEN 1 END) as total_texto,
        COUNT(CASE WHEN r.comentario = 'NOK' AND te.tipo_resultado = 'BOOLEANO' THEN 1 END) as fallidos_booleanos,
        COUNT(CASE WHEN r.comentario = 'NOK' AND te.tipo_resultado = 'NUMERICO' THEN 1 END) as fallidos_numericos,
        COUNT(CASE WHEN r.comentario = 'NOK' AND te.tipo_resultado = 'TEXTO' THEN 1 END) as fallidos_texto,
        COUNT(CASE WHEN r.comentario = 'NOK' THEN 1 END) as total_fallidos
      FROM resultados_ensayos re
      JOIN tipos_ensayo te ON re.id_tipo_ensayo = te.id_tipo_ensayo
      LEFT JOIN reglas_resultados_ensayos r ON re.id_tipo_ensayo = r.id_tipo_ensayo
      WHERE (
        (te.tipo_resultado = 'BOOLEANO' AND (
          (r.valor_booleano IS NOT NULL AND re.resultado_booleano = r.valor_booleano) OR
          (r.valor_booleano IS NULL AND re.resultado_booleano = false)
        )) OR
        (te.tipo_resultado = 'NUMERICO' AND re.resultado_numerico IS NOT NULL AND (
          (r.tipo_condicion = '=' AND re.resultado_numerico = r.valor_numerico_1) OR
          (r.tipo_condicion = '<>' AND re.resultado_numerico != r.valor_numerico_1) OR
          (r.tipo_condicion = '>' AND re.resultado_numerico > r.valor_numerico_1) OR
          (r.tipo_condicion = '<' AND re.resultado_numerico < r.valor_numerico_1) OR
          (r.tipo_condicion = '>=' AND re.resultado_numerico >= r.valor_numerico_1) OR
          (r.tipo_condicion = '<=' AND re.resultado_numerico <= r.valor_numerico_1) OR
          (r.tipo_condicion = 'ENTRE' AND re.resultado_numerico >= r.valor_numerico_1 AND re.resultado_numerico <= r.valor_numerico_2) OR
          (r.tipo_condicion = 'FUERA_DE' AND (re.resultado_numerico < r.valor_numerico_1 OR re.resultado_numerico > r.valor_numerico_2))
        )) OR
        (te.tipo_resultado = 'TEXTO' AND re.resultado_texto IS NOT NULL AND (
          (r.tipo_condicion = '=' AND re.resultado_texto = r.valor_texto) OR
          (r.tipo_condicion = '<>' AND re.resultado_texto != r.valor_texto)
        ))
      )
    `
    
    const ensayosFallidosResult = await pool.query(ensayosFallidosQuery)
    const fallosData = ensayosFallidosResult.rows[0]
    
    const totalEnsayosBooleanos = parseInt(fallosData.total_booleanos || 0)
    const ensayosFallidosBooleanos = parseInt(fallosData.fallidos_booleanos || 0)
    const ensayosFallidosNumericos = parseInt(fallosData.fallidos_numericos || 0)
    const ensayosFallidosTexto = parseInt(fallosData.fallidos_texto || 0)
    const ensayosFallidos = parseInt(fallosData.total_fallidos || 0)
    
    // Calculate success rate
    const tasaExito = totalEnsayos > 0 ? Math.round(((totalEnsayos - ensayosFallidos) / totalEnsayos) * 100 * 10) / 10 : 100
    
    // Get number of inspected tables
    const mesasInspeccionadasQuery = 'SELECT COUNT(DISTINCT id_mesa) as total FROM resultados_ensayos'
    const mesasInspeccionadasResult = await pool.query(mesasInspeccionadasQuery)
    const mesasInspeccionadas = parseInt(mesasInspeccionadasResult.rows[0].total)
    
    // Get active inspections
    const inspeccionesActivasQuery = "SELECT COUNT(*) as total FROM inspecciones WHERE estado = 'EN_PROCESO'"
    const inspeccionesActivasResult = await pool.query(inspeccionesActivasQuery)
    const inspeccionesActivas = parseInt(inspeccionesActivasResult.rows[0].total)
    
    // Get tests by type (HINCAS vs POT)
    const ensayosPorTipoQuery = `
      SELECT 
        COALESCE(te.grupo_ensayo, 'SIN_GRUPO') as tipo, 
        COUNT(re.id_resultado) as cantidad
      FROM resultados_ensayos re
      JOIN tipos_ensayo te ON re.id_tipo_ensayo = te.id_tipo_ensayo
      GROUP BY te.grupo_ensayo
      ORDER BY cantidad DESC
    `
    const ensayosPorTipoResult = await pool.query(ensayosPorTipoQuery)
    const ensayosPorTipo = ensayosPorTipoResult.rows
    
    // Get results by test result type using NOK comentario
    const ensayosPorTipoResultadoQuery = `
      SELECT 
        te.tipo_resultado as tipo,
        COUNT(re.id_resultado) as cantidad,
        COUNT(CASE WHEN r.comentario = 'NOK' THEN 1 END) as fallidos_booleanos
      FROM resultados_ensayos re
      JOIN tipos_ensayo te ON re.id_tipo_ensayo = te.id_tipo_ensayo
      LEFT JOIN reglas_resultados_ensayos r ON re.id_tipo_ensayo = r.id_tipo_ensayo
      GROUP BY te.tipo_resultado
      ORDER BY cantidad DESC
    `
    const ensayosPorTipoResultadoResult = await pool.query(ensayosPorTipoResultadoQuery)
    const ensayosPorTipoResultado = ensayosPorTipoResultadoResult.rows
    
    // Get temporal evolution (last 7 days with cumulative totals)
    const evolucionTemporalQuery = `
      WITH date_series AS (
        SELECT generate_series(
          CURRENT_DATE - INTERVAL '6 days',
          CURRENT_DATE,
          INTERVAL '1 day'
        )::date as fecha
      ),
      daily_counts AS (
        SELECT 
          DATE(re.fecha_medicion) as fecha,
          COUNT(re.id_resultado) as cantidad_dia
        FROM resultados_ensayos re
        WHERE DATE(re.fecha_medicion) >= CURRENT_DATE - INTERVAL '6 days'
        GROUP BY DATE(re.fecha_medicion)
      ),
      cumulative_before_period AS (
        SELECT COUNT(*) as total_anterior
        FROM resultados_ensayos
        WHERE DATE(fecha_medicion) < CURRENT_DATE - INTERVAL '6 days'
      )
      SELECT 
        ds.fecha,
        COALESCE(
          (SELECT total_anterior FROM cumulative_before_period) +
          (SELECT COALESCE(SUM(dc2.cantidad_dia), 0) 
           FROM daily_counts dc2 
           WHERE dc2.fecha <= ds.fecha),
          (SELECT total_anterior FROM cumulative_before_period)
        ) as cantidad_acumulada
      FROM date_series ds
      ORDER BY ds.fecha
    `
    const evolucionTemporalResult = await pool.query(evolucionTemporalQuery)
    const evolucionTemporal = evolucionTemporalResult.rows.map((row: any) => {
      const fecha = new Date(row.fecha);
      const dia = fecha.getDate().toString().padStart(2, '0');
      const mes = (fecha.getMonth() + 1).toString().padStart(2, '0');
      return {
        fecha: `${dia}/${mes}`, // Format as DD/MM
        cantidad: parseInt(row.cantidad_acumulada)
      };
    })
    
    // Get total components for "Sin medición" calculation
    const totalComponentesQuery = `
      SELECT COUNT(*) as total
      FROM mesas m
      JOIN plantilla_componentes pc ON m.id_plantilla = pc.id_plantilla
    `
    const totalComponentesResult = await pool.query(totalComponentesQuery)
    const totalComponentes = parseInt(totalComponentesResult.rows[0].total)

    // Get pie chart data for each HINCAS test type (only latest result per component)
    const pieChartsDataQuery = `
      WITH latest_results AS (
        SELECT 
          re.id_tipo_ensayo,
          re.id_mesa,
          re.id_componente_plantilla_1,
          re.resultado_numerico,
          re.resultado_booleano,
          re.resultado_texto,
          ROW_NUMBER() OVER (
            PARTITION BY re.id_tipo_ensayo, re.id_mesa, re.id_componente_plantilla_1 
            ORDER BY re.fecha_medicion DESC
          ) as rn
        FROM resultados_ensayos re
      )
      SELECT 
        te.id_tipo_ensayo,
        te.nombre_ensayo,
        te.tipo_resultado,
        r.comentario as categoria,
        COUNT(lr.id_tipo_ensayo) as cantidad,
        CASE 
          WHEN r.comentario = 'OK' THEN '#10b981'
          WHEN r.comentario = 'NOK' THEN '#F54927'
          ELSE '#6366f1'
        END as color
      FROM tipos_ensayo te
      LEFT JOIN reglas_resultados_ensayos r ON te.id_tipo_ensayo = r.id_tipo_ensayo
      LEFT JOIN latest_results lr ON (
        te.id_tipo_ensayo = lr.id_tipo_ensayo AND 
        lr.rn = 1 AND
        (
          (r.valor_booleano IS NOT NULL AND lr.resultado_booleano = r.valor_booleano) OR
          (r.valor_numerico_1 IS NOT NULL AND (
            (r.tipo_condicion = '=' AND lr.resultado_numerico = r.valor_numerico_1) OR
            (r.tipo_condicion = '<>' AND lr.resultado_numerico != r.valor_numerico_1) OR
            (r.tipo_condicion = '>' AND lr.resultado_numerico > r.valor_numerico_1) OR
            (r.tipo_condicion = '<' AND lr.resultado_numerico < r.valor_numerico_1) OR
            (r.tipo_condicion = '>=' AND lr.resultado_numerico >= r.valor_numerico_1) OR
            (r.tipo_condicion = '<=' AND lr.resultado_numerico <= r.valor_numerico_1) OR
            (r.tipo_condicion = 'ENTRE' AND lr.resultado_numerico >= r.valor_numerico_1 AND lr.resultado_numerico <= r.valor_numerico_2) OR
            (r.tipo_condicion = 'FUERA_DE' AND (lr.resultado_numerico < r.valor_numerico_1 OR lr.resultado_numerico > r.valor_numerico_2))
          )) OR
          (r.valor_texto IS NOT NULL AND (
            (r.tipo_condicion = '=' AND lr.resultado_texto = r.valor_texto) OR
            (r.tipo_condicion = '<>' AND lr.resultado_texto != r.valor_texto)
          ))
        )
      )
      WHERE te.grupo_ensayo = 'HINCAS' AND r.comentario IN ('OK', 'NOK')
      GROUP BY te.id_tipo_ensayo, te.nombre_ensayo, te.tipo_resultado, r.comentario
      ORDER BY te.nombre_ensayo, r.comentario
    `
    const pieChartsResult = await pool.query(pieChartsDataQuery)
    
    // Group pie chart data by test type
    const pieChartsData: any = {};
    pieChartsResult.rows.forEach((row: any) => {
      if (!pieChartsData[row.id_tipo_ensayo]) {
        pieChartsData[row.id_tipo_ensayo] = {
          nombre_ensayo: row.nombre_ensayo,
          tipo_resultado: row.tipo_resultado,
          data: []
        };
      }
      pieChartsData[row.id_tipo_ensayo].data.push({
        categoria: row.categoria,
        cantidad: parseInt(row.cantidad),
        color: row.color
      });
    });

    // Add "Sin medición" category for each test type
    for (const tipoEnsayoId in pieChartsData) {
      const chartData = pieChartsData[tipoEnsayoId];
      
      // Count total measured for this specific test type (only latest results per component)
      const totalMedidosQuery = `
        SELECT COUNT(DISTINCT (id_mesa, id_componente_plantilla_1)) as total
        FROM (
          SELECT 
            id_mesa,
            id_componente_plantilla_1,
            ROW_NUMBER() OVER (
              PARTITION BY id_tipo_ensayo, id_mesa, id_componente_plantilla_1 
              ORDER BY fecha_medicion DESC
            ) as rn
          FROM resultados_ensayos
          WHERE id_tipo_ensayo = $1
        ) latest_only
        WHERE rn = 1
      `
      const totalMedidosResult = await pool.query(totalMedidosQuery, [tipoEnsayoId])
      const totalMedidos = parseInt(totalMedidosResult.rows[0].total)
      
      // Calculate "Sin medición" for this test type
      const sinMedicion = totalComponentes - totalMedidos
      
      if (sinMedicion > 0) {
        chartData.data.push({
          categoria: 'Sin medición',
          cantidad: sinMedicion,
          color: '#94a3b8'
        });
      }
    }
    
    const estadisticas = {
      totalEnsayos,
      ensayosFallidos,
      ensayosFallidosBooleanos,
      ensayosFallidosNumericos,
      ensayosFallidosTexto,
      totalEnsayosBooleanos,
      tasaExito,
      mesasInspeccionadas,
      evolucionTemporal,
      pieChartsData,
      totalComponentes
    }
    
    console.log('📈 Real dashboard statistics generated:', {
      ...estadisticas,
      pieChartsData: Object.keys(estadisticas.pieChartsData).length
    })
    return c.json(estadisticas)
    
  } catch (error) {
    console.error('Error fetching dashboard statistics:', error)
    return c.json({ error: 'Failed to fetch dashboard statistics' }, 500)
  }
})

// Get all mesas for Excel report generator
app.get('/api/mesas', authMiddleware, async (c) => {
  try {
    console.log('📋 Fetching all mesas for Excel report generator...')
    
    const query = `
      SELECT 
        m.id_mesa,
        m.id_ct,
        m.nombre_mesa,
        ct.nombre_ct,
        mp.nombre_plantilla
      FROM mesas m
      JOIN mesa_plantillas mp ON m.id_plantilla = mp.id_plantilla
      JOIN cts ct ON m.id_ct = ct.id_ct
      ORDER BY m.id_mesa
    `
    
    const result = await pool.query(query)
    console.log(`📋 Found ${result.rows.length} mesas`)
    return c.json(result.rows)
    
  } catch (error) {
    console.error('Error fetching mesas:', error)
    return c.json({ error: 'Failed to fetch mesas' }, 500)
  }
})

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
  
  // 5. Process each component that has POT tests
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
    
    console.log(`📋 Created new POT worksheet: Mesa_${component.nombre_mesa}_Comp_${component.id_componente}`)
    
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
              const hincaInfo = component.descripcion_punto_montaje || `Componente ${component.id_componente}`
              newCell.value = cellValue.replace('[hinca]', hincaInfo)
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
              // Concatenar comentarios de medidas verticales (v) con salto de línea
              const vComments = []
              const ids_tipos_v = [24, 25, 26] // tipos de ensayo verticales
              ids_tipos_v.forEach(id_tipo => {
                const result = resultsMap.get(`${component.id_mesa}-${component.id_componente}-${id_tipo}`)
                if (result?.comentario) {
                  vComments.push(result.comentario)
                }
              })
              newCell.value = cellValue.replace('[v_comentario]', vComments.join('\n'))
            } else if (cellValue.includes('[v_valido]')) {
              // Campo calculado basado en T1 y T2 de este componente específico
              const resultT1 = resultsMap.get(`${component.id_mesa}-${component.id_componente}-25`)
              const resultT2 = resultsMap.get(`${component.id_mesa}-${component.id_componente}-26`)
              const isValid = (resultT1?.numerico !== null && resultT1?.numerico !== undefined) && 
                             (resultT2?.numerico !== null && resultT2?.numerico !== undefined)
              newCell.value = cellValue.replace('[v_valido]', isValid ? '✓' : '✗')
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
              // Campo calculado basado en cortantes T1 y T2 de este componente específico
              const resultT1 = resultsMap.get(`${component.id_mesa}-${component.id_componente}-29`)
              const resultT2 = resultsMap.get(`${component.id_mesa}-${component.id_componente}-26`)
              const isValid = (resultT1?.numerico !== null && resultT1?.numerico !== undefined) && 
                             (resultT2?.numerico !== null && resultT2?.numerico !== undefined)
              newCell.value = cellValue.replace('[c_valido]', isValid ? '✓' : '✗')
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

// Export mesas table
app.get('/api/export/mesas', exportAuthMiddleware, async (c) => {
  try {
    const result = await pool.query(`
      SELECT 
        m.*,
        c.nombre_ct,
        p.nombre_plantilla,
        p.dimension_x,
        p.dimension_y
      FROM mesas m
      LEFT JOIN cts c ON m.id_ct = c.id_ct
      LEFT JOIN mesa_plantillas p ON m.id_plantilla = p.id_plantilla
      ORDER BY m.id_mesa
    `)
    return c.json(result.rows)
  } catch (error) {
    console.error('Error exporting mesas:', error)
    return c.json({ error: 'Failed to export mesas' }, 500)
  }
})

// Export resultados_ensayos table
app.get('/api/export/resultados-ensayos', exportAuthMiddleware, async (c) => {
  try {
    const result = await pool.query(`
      SELECT 
        re.*,
        te.nombre_ensayo,
        te.descripcion as ensayo_descripcion,
        te.unidad_medida,
        te.grupo_ensayo,
        te.tipo_resultado,
        m.nombre_mesa,
        m.id_ct,
        c.nombre_ct,
        pc1.descripcion_punto_montaje as componente_1_descripcion,
        pc1.tipo_elemento as componente_1_tipo,
        pc1.coord_x as componente_1_coord_x,
        pc1.coord_y as componente_1_coord_y,
        pc2.descripcion_punto_montaje as componente_2_descripcion,
        pc2.tipo_elemento as componente_2_tipo,
        pc2.coord_x as componente_2_coord_x,
        pc2.coord_y as componente_2_coord_y
      FROM resultados_ensayos re
      LEFT JOIN tipos_ensayo te ON re.id_tipo_ensayo = te.id_tipo_ensayo
      LEFT JOIN mesas m ON re.id_mesa = m.id_mesa
      LEFT JOIN cts c ON m.id_ct = c.id_ct
      LEFT JOIN plantilla_componentes pc1 ON re.id_componente_plantilla_1 = pc1.id_componente
      LEFT JOIN plantilla_componentes pc2 ON re.id_componente_plantilla_2 = pc2.id_componente
      ORDER BY re.id_mesa, te.nombre_ensayo, re.fecha_medicion DESC
    `)
    return c.json(result.rows)
  } catch (error) {
    console.error('Error exporting resultados_ensayos:', error)
    return c.json({ error: 'Failed to export resultados_ensayos' }, 500)
  }
})

// Export tipos_ensayo table
app.get('/api/export/tipos-ensayo', exportAuthMiddleware, async (c) => {
  try {
    const result = await pool.query(`
      SELECT * FROM tipos_ensayo ORDER BY grupo_ensayo, orden_prioridad, nombre_ensayo
    `)
    return c.json(result.rows)
  } catch (error) {
    console.error('Error exporting tipos_ensayo:', error)
    return c.json({ error: 'Failed to export tipos_ensayo' }, 500)
  }
})

// Export reglas_resultados_ensayos table  
app.get('/api/export/reglas-resultados-ensayos', exportAuthMiddleware, async (c) => {
  try {
    const result = await pool.query(`
      SELECT 
        r.*,
        te.nombre_ensayo,
        te.tipo_resultado
      FROM reglas_resultados_ensayos r
      LEFT JOIN tipos_ensayo te ON r.id_tipo_ensayo = te.id_tipo_ensayo
      ORDER BY r.id_tipo_ensayo, r.prioridad
    `)
    return c.json(result.rows)
  } catch (error) {
    console.error('Error exporting reglas_resultados_ensayos:', error)
    return c.json({ error: 'Failed to export reglas_resultados_ensayos' }, 500)
  }
})

// Export plantilla_componentes table
app.get('/api/export/plantilla-componentes', exportAuthMiddleware, async (c) => {
  try {
    const result = await pool.query(`
      SELECT 
        pc.*,
        p.nombre_plantilla
      FROM plantilla_componentes pc
      LEFT JOIN mesa_plantillas p ON pc.id_plantilla = p.id_plantilla
      ORDER BY pc.id_plantilla, pc.orden_prioridad, pc.id_componente
    `)
    return c.json(result.rows)
  } catch (error) {
    console.error('Error exporting plantilla_componentes:', error)
    return c.json({ error: 'Failed to export plantilla_componentes' }, 500)
  }
})

// Export specific inspection data (JSON format)
app.get('/api/export/inspecciones/:id/resultados', exportAuthMiddleware, async (c) => {
  try {
    const inspectionId = c.req.param('id')
    const result = await pool.query(`
      SELECT 
        re.*,
        te.nombre_ensayo,
        te.descripcion as ensayo_descripcion,
        te.unidad_medida,
        te.grupo_ensayo,
        te.tipo_resultado,
        m.nombre_mesa,
        m.id_ct,
        c.nombre_ct,
        pc1.descripcion_punto_montaje as componente_1_descripcion,
        pc1.tipo_elemento as componente_1_tipo,
        pc1.coord_x as componente_1_coord_x,
        pc1.coord_y as componente_1_coord_y
      FROM resultados_ensayos re
      LEFT JOIN tipos_ensayo te ON re.id_tipo_ensayo = te.id_tipo_ensayo
      LEFT JOIN mesas m ON re.id_mesa = m.id_mesa
      LEFT JOIN cts c ON m.id_ct = c.id_ct
      LEFT JOIN plantilla_componentes pc1 ON re.id_componente_plantilla_1 = pc1.id_componente
      WHERE re.id_inspeccion = $1
      ORDER BY re.id_mesa, te.nombre_ensayo, re.fecha_medicion DESC
    `, [inspectionId])
    return c.json(result.rows)
  } catch (error) {
    console.error('Error exporting inspection results:', error)
    return c.json({ error: 'Failed to export inspection results' }, 500)
  }
})

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

// Helper functions for result formatting
function evaluateRule(rule: any, result: any): boolean {
  const { tipo_condicion, valor_numerico_1, valor_numerico_2, valor_booleano, valor_texto } = rule;
  
  // Get result value and convert to correct type
  let resultValue;
  if (result.resultado_numerico !== null && result.resultado_numerico !== undefined) {
    resultValue = parseFloat(result.resultado_numerico);
  } else if (result.resultado_booleano !== null && result.resultado_booleano !== undefined) {
    resultValue = result.resultado_booleano;
  } else if (result.resultado_texto !== null && result.resultado_texto !== undefined) {
    resultValue = result.resultado_texto;
  } else {
    return false;
  }
  
  const num1 = valor_numerico_1 !== null ? parseFloat(valor_numerico_1) : null;
  const num2 = valor_numerico_2 !== null ? parseFloat(valor_numerico_2) : null;
  
  // Enhanced debug for boolean rule evaluation with explicit conversion
  if (typeof resultValue === 'boolean') {
    console.log(`[PDF-RULE] Evaluating boolean: result=${resultValue} ${tipo_condicion} rule_value=${valor_booleano}`);
    
    // Explicit comparison for debugging
    let ruleMatch = false;
    if (tipo_condicion === '=') {
      ruleMatch = resultValue === valor_booleano;
    } else if (tipo_condicion === '<>') {
      ruleMatch = resultValue !== valor_booleano;
    }
    
    console.log(`[PDF-RULE] Match result: ${ruleMatch} (${resultValue} ${tipo_condicion} ${valor_booleano})`);
  }
  
  switch (tipo_condicion) {
    case '=':
      if (typeof resultValue === 'number' && num1 !== null) return resultValue === num1;
      if (typeof resultValue === 'boolean') return resultValue === valor_booleano;
      if (typeof resultValue === 'string') return resultValue === valor_texto;
      break;
    
    case '<>':
      if (typeof resultValue === 'number' && num1 !== null) return resultValue !== num1;
      if (typeof resultValue === 'boolean') return resultValue !== valor_booleano;
      if (typeof resultValue === 'string') return resultValue !== valor_texto;
      break;
    
    case '>':
      if (typeof resultValue === 'number' && num1 !== null) return resultValue > num1;
      break;
    
    case '<':
      if (typeof resultValue === 'number' && num1 !== null) return resultValue < num1;
      break;
    
    case '>=':
      if (typeof resultValue === 'number' && num1 !== null) return resultValue >= num1;
      break;
    
    case '<=':
      if (typeof resultValue === 'number' && num1 !== null) return resultValue <= num1;
      break;
    
    case 'ENTRE':
      if (typeof resultValue === 'number' && num1 !== null && num2 !== null) {
        return resultValue >= num1 && resultValue <= num2;
      }
      break;
    
    case 'FUERA_DE':
      if (typeof resultValue === 'number' && num1 !== null && num2 !== null) {
        return resultValue < num1 || resultValue > num2;
      }
      break;
  }
  
  return false;
}

function getCellBackgroundColor(component: any, tipoEnsayo: any, results: any[], colorRules: any[]): string | null {
  const result = results.find(r => 
    r.id_componente_plantilla_1 === component.id_componente && 
    r.id_tipo_ensayo === tipoEnsayo.id_tipo_ensayo
  );
  
  if (!result) {
    return null;
  }
  
  const applicableRules = colorRules.filter(rule => 
    rule.id_tipo_ensayo === tipoEnsayo.id_tipo_ensayo
  );
  
  applicableRules.sort((a, b) => a.prioridad - b.prioridad);
  
  // Enhanced debug for boolean color rules
  if (result.resultado_booleano !== null && result.resultado_booleano !== undefined) {
    console.log(`[PDF-COLOR] Component ${component.id_componente}, Test ${tipoEnsayo.id_tipo_ensayo}: value=${result.resultado_booleano} (${typeof result.resultado_booleano}), rules=${applicableRules.length}`);
    applicableRules.forEach((rule, index) => {
      console.log(`  Rule ${index}: condition=${rule.tipo_condicion}, rule_bool=${rule.valor_booleano}, color=${rule.resaltado}`);
    });
  }
  
  for (const rule of applicableRules) {
    const ruleMatches = evaluateRule(rule, result);
    
    if (ruleMatches) {
      const colorHex = rule.resaltado.startsWith('#') ? rule.resaltado : `#${rule.resaltado}`;
      console.log(`[PDF-COLOR] ✅ Rule matched for component ${component.id_componente}: ${colorHex}`);
      return colorHex;
    }
  }
  
  return null;
}

function formatTestResult(component: any, tipoEnsayo: any, results: any[]): string {
  const result = results.find(r => 
    r.id_componente_plantilla_1 === component.id_componente && 
    r.id_tipo_ensayo === tipoEnsayo.id_tipo_ensayo
  );
  
  // Simplified debug - only log when no match found
  if (!result) {
    console.log(`[PDF-MATCH] No result for component ${component.id_componente}, test ${tipoEnsayo.id_tipo_ensayo}`);
    return '-';
  }
  
  let value = '';
  if (result.resultado_numerico !== null && result.resultado_numerico !== undefined) {
    value = `${result.resultado_numerico}${tipoEnsayo.unidad_medida ? ' ' + tipoEnsayo.unidad_medida : ''}`;
  } else if (result.resultado_booleano !== null && result.resultado_booleano !== undefined) {
    // Explicit boolean conversion and debug
    let boolValue;
    if (result.resultado_booleano === true || result.resultado_booleano === 'true' || result.resultado_booleano === 1) {
      boolValue = true;
    } else if (result.resultado_booleano === false || result.resultado_booleano === 'false' || result.resultado_booleano === 0) {
      boolValue = false;
    } else {
      boolValue = Boolean(result.resultado_booleano);
    }
    
    const icon = boolValue ? '✅' : '❌';
    console.log(`[PDF-BOOL] Component ${component.id_componente}, Test ${tipoEnsayo.nombre_ensayo}: DB=${result.resultado_booleano}(${typeof result.resultado_booleano}) -> ${boolValue} -> ${icon}`);
    value = icon;
  } else if (result.resultado_texto) {
    value = result.resultado_texto;
  }
  
  if (result.comentario && result.comentario.trim()) {
    value = `* ${value}`;
  }
  
  return value;
}

// Helper function to generate HTML for PDF
function generateReportHTML(reportData: any) {
  const { inspection, mesas, tiposEnsayo, colorRules } = reportData
  
  return `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <title>Informe Inspección #${inspection.id_inspeccion}</title>
      <style>
        ${getPDFStyles()}
      </style>
    </head>
    <body>
      <!-- Página 1: Información de la inspección -->
      <div class="report-cover-page">
        <div class="report-header-logo">
          <h1>📋 INFORME DE INSPECCIÓN</h1>
          <div class="report-subtitle">Sistema de Inspecciones de Hincado</div>
        </div>
        
        <div class="inspection-summary">
          <h2>Datos de la Inspección</h2>
          <div class="summary-grid">
            <div class="summary-item">
              <span class="summary-label">ID Inspección:</span>
              <span class="summary-value">#${inspection.id_inspeccion}</span>
            </div>
            <div class="summary-item">
              <span class="summary-label">Fecha de Inicio:</span>
              <span class="summary-value">${new Date(inspection.fecha_inicio).toLocaleString('es-ES')}</span>
            </div>
            ${inspection.fecha_fin ? `
            <div class="summary-item">
              <span class="summary-label">Fecha de Fin:</span>
              <span class="summary-value">${new Date(inspection.fecha_fin).toLocaleString('es-ES')}</span>
            </div>
            ` : ''}
            <div class="summary-item">
              <span class="summary-label">Estado:</span>
              <span class="summary-value">${inspection.estado}</span>
            </div>
            ${inspection.descripcion ? `
            <div class="summary-item full-width">
              <span class="summary-label">Descripción:</span>
              <span class="summary-value">${inspection.descripcion}</span>
            </div>
            ` : ''}
          </div>
        </div>

        <div class="mesas-summary">
          <h2>Resumen de Mesas Inspeccionadas</h2>
          <p><strong>Total de mesas:</strong> ${mesas.length}</p>
          
          <table class="summary-table">
            <thead>
              <tr>
                <th>ID Mesa</th>
                <th>Nombre</th>
                <th>CT</th>
                <th>Total Ensayos</th>
              </tr>
            </thead>
            <tbody>
              ${mesas.map(mesa => `
                <tr>
                  <td>${mesa.id_mesa}</td>
                  <td>${mesa.nombre_mesa}</td>
                  <td>${mesa.nombre_ct || 'N/A'}</td>
                  <td>${mesa.results?.length || 0}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>

        <div class="report-footer">
          <p><strong>Informe generado:</strong> ${new Date(reportData.generated_at).toLocaleString('es-ES')}</p>
          <p><strong>Sistema:</strong> Inspecciones Hincado v1.0</p>
        </div>
      </div>

      <!-- Páginas siguientes: Una tabla por mesa -->
      ${mesas.map((mesa, index) => `
        <div class="mesa-report-page${index === mesas.length - 1 ? ' last-mesa' : ''}">
          <div class="mesa-page-header">
            <div>
              <h2>Mesa: ${mesa.nombre_mesa} (ID: ${mesa.id_mesa})</h2>
            </div>
            <div class="mesa-details">
              <span><strong>CT:</strong> ${mesa.nombre_ct || 'N/A'}</span>
              <span><strong>Coordenadas:</strong> 
                (${typeof mesa.coord_x === 'number' ? mesa.coord_x.toFixed(6) : mesa.coord_x || 'N/A'}, 
                 ${typeof mesa.coord_y === 'number' ? mesa.coord_y.toFixed(6) : mesa.coord_y || 'N/A'})
              </span>
              <span><strong>Página:</strong> ${index + 2}/${mesas.length + 1}</span>
            </div>
          </div>

          ${mesa.components && mesa.components.length > 0 && tiposEnsayo && tiposEnsayo.length > 0 ? `
            <table class="mesa-results-table">
              <thead>
                <tr>
                  <th class="component-header">Componente</th>
                  <th class="coordinates-header">Coordenadas</th>
                  ${tiposEnsayo.map(tipoEnsayo => `
                    <th class="test-header">
                      ${tipoEnsayo.nombre_ensayo}
                      ${tipoEnsayo.unidad_medida ? `<br><small>(${tipoEnsayo.unidad_medida})</small>` : ''}
                    </th>
                  `).join('')}
                </tr>
              </thead>
              <tbody>
                ${mesa.components.map(component => `
                  <tr>
                    <td class="component-cell">
                      <span class="component-icon">
                        ${component.tipo_elemento === 'PANEL' ? '🔆' : '🔧'}
                      </span>
                      ${component.descripcion_punto_montaje || `${component.tipo_elemento} ${component.id_componente}`}
                    </td>
                    <td class="coordinates-cell">
                      (${Math.round(component.coord_x)}, ${Math.round(component.coord_y)})
                    </td>
                    ${tiposEnsayo.map(tipoEnsayo => {
                      const bgColor = getCellBackgroundColor(component, tipoEnsayo, mesa.results, colorRules);
                      const resultText = formatTestResult(component, tipoEnsayo, mesa.results);
                      const styleAttr = bgColor ? ` style="background-color: ${bgColor} !important;"` : '';
                      
                      return `<td class="result-cell"${styleAttr}>${resultText}</td>`
                    }).join('')}
                  </tr>
                `).join('')}
              </tbody>
            </table>
          ` : `
            <div class="no-results">
              <p>No se encontraron datos para esta mesa.</p>
              <p><small>Componentes: ${mesa.components?.length || 0}, Tipos ensayo: ${tiposEnsayo?.length || 0}</small></p>
            </div>
          `}

        </div>
      `).join('')}
    </body>
    </html>
  `
}

// CSS styles for PDF
function getPDFStyles() {
  return `
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }
    
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif;
      line-height: 1.4;
      color: #333;
    }
    
    .report-cover-page {
      width: 100%;
      min-height: 100vh;
      page-break-after: always;
      page-break-inside: avoid;
      padding: 20mm;
      margin: 0;
      box-sizing: border-box;
    }
    
    @page {
      size: A4;
      margin: 15mm;
    }
    
    @page landscape {
      size: A4 landscape;
      margin: 15mm;
    }
    
    .mesa-report-page {
      width: 100%;
      page-break-after: always;
      padding: 10mm;
      margin: 0;
      box-sizing: border-box;
      page: landscape;
    }
    
    .mesa-report-page.last-mesa {
      page-break-after: avoid !important;
    }
    
    .report-header-logo {
      text-align: center;
      margin-bottom: 30px;
      border-bottom: 2px solid #333;
      padding-bottom: 20px;
    }
    
    .report-header-logo h1 {
      font-size: 28px;
      font-weight: bold;
      margin: 0;
      color: #333;
    }
    
    .report-subtitle {
      font-size: 16px;
      color: #666;
      margin-top: 10px;
    }
    
    .inspection-summary h2,
    .mesas-summary h2 {
      font-size: 20px;
      margin-bottom: 15px;
      color: #333;
      border-bottom: 1px solid #ddd;
      padding-bottom: 5px;
    }
    
    .summary-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 15px;
      margin-bottom: 30px;
    }
    
    .summary-item {
      display: flex;
      flex-direction: column;
      gap: 5px;
    }
    
    .summary-item.full-width {
      grid-column: 1 / -1;
    }
    
    .summary-label {
      font-weight: bold;
      color: #555;
    }
    
    .summary-value {
      color: #333;
    }
    
    .summary-table {
      width: 100%;
      border-collapse: collapse;
      margin-bottom: 30px;
    }
    
    .summary-table th,
    .summary-table td {
      border: 1px solid #ddd;
      padding: 8px;
      text-align: left;
    }
    
    .summary-table th {
      background-color: #f8f9fa;
      font-weight: bold;
    }
    
    .mesa-page-header {
      margin-bottom: 15px;
      border-bottom: 1px solid #ccc;
      padding-bottom: 10px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    
    .mesa-page-header h2 {
      font-size: 16px;
      margin: 0;
      color: #333;
    }
    
    .mesa-details {
      font-size: 11px;
      color: #666;
      display: flex;
      gap: 15px;
    }
    
    .mesa-results-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 9px;
      margin-top: 5px;
      table-layout: fixed;
    }
    
    .mesa-results-table th,
    .mesa-results-table td {
      border: 1px solid #333;
      padding: 2px 4px;
      text-align: center;
      word-wrap: break-word;
      overflow: hidden;
      max-width: 80px;
    }
    
    .mesa-results-table th {
      background-color: #f0f0f0;
      font-weight: bold;
      font-size: 7px;
      line-height: 1.2;
    }
    
    .mesa-results-table .component-header {
      text-align: left !important;
      width: 120px;
      min-width: 120px;
    }
    
    .mesa-results-table .component-cell {
      text-align: left !important;
      font-size: 8px;
      width: 120px;
      min-width: 120px;
    }
    
    .mesa-results-table .coordinates-header {
      width: 60px;
      min-width: 60px;
    }
    
    .mesa-results-table .coordinates-cell {
      font-size: 7px;
      color: #666;
      width: 60px;
      min-width: 60px;
    }
    
    .mesa-results-table .test-header {
      width: 45px;
      min-width: 45px;
      font-size: 7px;
      line-height: 1.1;
    }
    
    .mesa-results-table .result-cell {
      font-size: 8px;
      font-weight: normal;
      width: 45px;
      min-width: 45px;
    }
    
    .component-icon {
      margin-right: 4px;
    }
    
    
    .report-footer {
      margin-top: 30px;
      text-align: center;
      font-size: 12px;
      color: #666;
    }
    
    .no-results {
      text-align: center;
      color: #666;
      font-style: italic;
      padding: 20px;
    }
    
    .mesa-results-table tbody tr {
      page-break-inside: auto;
    }
    
    .mesa-results-table {
      page-break-after: avoid;
    }
  `
}

// Start the server
const port = process.env.PORT ? parseInt(process.env.PORT) : 8787

serve({
  fetch: app.fetch,
  port,
})

console.log(`🚀 Server running on http://localhost:${port}`)
