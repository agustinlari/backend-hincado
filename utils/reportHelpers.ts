// Helper functions for result formatting and PDF generation

export function evaluateRule(rule: any, result: any): boolean {
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

export function getCellBackgroundColor(component: any, tipoEnsayo: any, results: any[], colorRules: any[]): string | null {
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

export function formatTestResult(component: any, tipoEnsayo: any, results: any[]): string {
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
export function generateReportHTML(reportData: any) {
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
          <table class="summary-table">
            <thead>
              <tr>
                <th>Mesa</th>
                <th>CT</th>
                <th>Plantilla</th>
                <th>Componentes</th>
              </tr>
            </thead>
            <tbody>
              ${mesas.map((mesa: any) => `
                <tr>
                  <td>${mesa.nombre_mesa}</td>
                  <td>${mesa.nombre_ct}</td>
                  <td>${mesa.nombre_plantilla || '-'}</td>
                  <td>${mesa.components?.length || 0}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>

      <!-- Páginas siguientes: Una página por mesa -->
      ${mesas.map((mesa: any, mesaIndex: number) => `
        <div class="mesa-report-page ${mesaIndex === mesas.length - 1 ? 'last-mesa' : ''}">
          <div class="mesa-page-header">
            <h2>Mesa: ${mesa.nombre_mesa}</h2>
            <div class="mesa-details">
              <span>CT: ${mesa.nombre_ct}</span>
              <span>Plantilla: ${mesa.nombre_plantilla || '-'}</span>
            </div>
          </div>

          ${mesa.components && mesa.components.length > 0 ? `
            <table class="mesa-results-table">
              <thead>
                <tr>
                  <th class="component-header">Componente</th>
                  <th class="coordinates-header">Coord</th>
                  ${tiposEnsayo.filter((te: any) => te.grupo_ensayo === 'HINCAS').map((tipoEnsayo: any) => `
                    <th class="test-header">${tipoEnsayo.nombre_ensayo}${tipoEnsayo.unidad_medida ? ' (' + tipoEnsayo.unidad_medida + ')' : ''}</th>
                  `).join('')}
                </tr>
              </thead>
              <tbody>
                ${mesa.components.map((component: any) => `
                  <tr>
                    <td class="component-cell">
                      <span class="component-icon">${component.tipo_elemento === 'PANEL' ? '📱' : '📍'}</span>
                      ${component.descripcion_punto_montaje || 'Sin descripción'}
                    </td>
                    <td class="coordinates-cell">${component.coord_x},${component.coord_y}</td>
                    ${tiposEnsayo.filter((te: any) => te.grupo_ensayo === 'HINCAS').map((tipoEnsayo: any) => {
                      const backgroundColor = getCellBackgroundColor(component, tipoEnsayo, mesa.results || [], colorRules);
                      const cellContent = formatTestResult(component, tipoEnsayo, mesa.results || []);
                      return `<td class="result-cell" ${backgroundColor ? `style="background-color: ${backgroundColor};"` : ''}>${cellContent}</td>`;
                    }).join('')}
                  </tr>
                `).join('')}
              </tbody>
            </table>
          ` : '<p class="no-results">No hay resultados disponibles para esta mesa</p>'}
        </div>
      `).join('')}

      <div class="report-footer">
        <p>Generado el ${new Date().toLocaleString('es-ES')}</p>
      </div>
    </body>
    </html>
  `
}

// CSS styles for PDF
export function getPDFStyles() {
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
