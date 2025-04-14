import { FileType, type PEAnalysisResult, type GeneralAnalysisResult } from "./types"

// Get the API base URL from environment variables
const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:5000/api"

/**
 * Uploads a file for malware analysis
 * @param file The file to analyze
 * @param fileType The type of file being analyzed
 * @returns The analysis result
 */
export async function uploadFileForAnalysis(file: File, fileType: FileType): Promise<any> {
  const formData = new FormData()
  formData.append("file", file)

  let endpoint = `${API_BASE_URL}/analyze`

  // Use the PE-specific endpoint for PE files
  if (fileType === FileType.PE) {
    endpoint = `${API_BASE_URL}/pe`
  }

  try {
    console.log(`Uploading file to ${endpoint}`)
    const response = await fetch(endpoint, {
      method: "POST",
      body: formData,
    })

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({ error: "Unknown error" }))
      throw new Error(errorData.error || `API error: ${response.status}`)
    }

    const result = await response.json()

    // Save the result to history
    saveToHistory(result, fileType)

    return result
  } catch (error) {
    console.error("Error uploading file:", error)
    throw error
  }
}

/**
 * Fetches analysis results for a specific file
 */
export async function fetchAnalysisResult(
  id: string,
  fileType: string,
): Promise<PEAnalysisResult | GeneralAnalysisResult> {
  try {
    const response = await fetch(`${API_BASE_URL}/results/${fileType}/${id}`)
    if (!response.ok) {
      throw new Error(`API error: ${response.status}`)
    }
    return await response.json()
  } catch (error) {
    console.error("Error fetching analysis result:", error)
    throw error
  }
}

/**
 * Saves analysis result to local storage history
 */
function saveToHistory(result: any, fileType: FileType): void {
  try {
    // Get existing history or initialize empty array
    const historyString = localStorage.getItem("scanHistory")
    const history = historyString ? JSON.parse(historyString) : []

    // Create history item
    const historyItem = {
      id: result.id || `scan-${Date.now()}`,
      fileName: result.filename || "Unknown file",
      fileType: fileType,
      scanDate: new Date().toISOString(),
      result: result.analysis_data?.summary?.prediction || "unknown",
      riskScore: result.analysis_data?.risk_metrics?.risk_score || 0,
      threatCount: result.analysis_data?.risk_metrics?.total_suspicious_features || 0,
    }

    // Add to beginning of array
    history.unshift(historyItem)

    // Keep only the last 25 items
    const trimmedHistory = history.slice(0, 25)

    // Save back to localStorage
    localStorage.setItem("scanHistory", JSON.stringify(trimmedHistory))
  } catch (error) {
    console.error("Error saving to history:", error)
  }
}

/**
 * Fetches scan history from local storage
 */
export function fetchScanHistory(): Promise<any[]> {
  return new Promise((resolve) => {
    try {
      const historyString = localStorage.getItem("scanHistory")
      const history = historyString ? JSON.parse(historyString) : []
      resolve(history)
    } catch (error) {
      console.error("Error fetching scan history:", error)
      resolve([])
    }
  })
}

/**
 * Clears scan history from local storage
 */
export function clearScanHistory(): Promise<void> {
  return new Promise((resolve) => {
    try {
      localStorage.removeItem("scanHistory")
      resolve()
    } catch (error) {
      console.error("Error clearing scan history:", error)
      resolve()
    }
  })
}

/**
 * Asks the AI assistant a question
 */
export async function askAI(question: string): Promise<string> {
  try {
    const response = await fetch(`${API_BASE_URL}/chat/ask`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ question }),
    })

    if (!response.ok) {
      throw new Error(`API error: ${response.status}`)
    }

    const data = await response.json()
    return data.response
  } catch (error) {
    console.error("Error asking AI:", error)
    throw error
  }
}


/**
 * Analyzes a JSON report using the AI assistant
 */
export async function analyzeReportWithAI(reportData: any): Promise<any> {
  try {
    const response = await fetch(`${API_BASE_URL}/chat/analyze`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(reportData),
    })

    if (!response.ok) {
      throw new Error(`API error: ${response.status}`)
    }

    return await response.json()
  } catch (error) {
    console.error("Error analyzing report with AI:", error)
    throw error
  }
}

/**
 * Generates a PDF report from analysis data
 */
export async function generatePDFReport(analysisData: any): Promise<Blob> {
  try {
    const response = await fetch(`${API_BASE_URL}/generate-report`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(analysisData),
    })

    if (!response.ok) {
      throw new Error(`API error: ${response.status}`)
    }

    return await response.blob()
  } catch (error) {
    console.error("Error generating PDF report:", error)
    throw error
  }
}

/**
 * Submits a file for dynamic analysis
 * @param file The file to analyze
 * @param apiKey Optional API key for VirusTotal
 * @returns The analysis result
 */
export async function submitDynamicAnalysis(file: File, apiKey?: string): Promise<any> {
  try {
    const formData = new FormData()
    formData.append("file", file)
    if (apiKey) {
      formData.append("api_key", apiKey)
    }

    const response = await fetch("/api/dynamic-analysis/scan", {
      method: "POST",
      body: formData,
    })

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({ error: "Unknown error" }))
      throw new Error(errorData.error || `API error: ${response.status}`)
    }

    return await response.json()
  } catch (error) {
    console.error("Error submitting file for dynamic analysis:", error)
    throw error
  }
}

/**
 * Fetches the results of a dynamic analysis
 */
export async function fetchDynamicAnalysisResults(analysisId: string): Promise<any> {
  try {
    const response = await fetch(`${API_BASE_URL}/dynamic-analysis/results/${analysisId}`)

    if (!response.ok) {
      throw new Error(`API error: ${response.status}`)
    }

    return await response.json()
  } catch (error) {
    console.error("Error fetching dynamic analysis results:", error)
    throw error
  }
}

/**
 * Generates a chat response from the AI
 */
export async function generateChatResponse(message: string, file?: File | null): Promise<string> {
  try {
    const formData = new FormData()
    formData.append("message", message)

    if (file) {
      formData.append("file", file)
    }

    const response = await fetch(`${API_BASE_URL}/chatbot`, {
      method: "POST",
      body: formData,
    })

    if (!response.ok) {
      throw new Error(`API error: ${response.status}`)
    }

    const data = await response.json()
    return data.response
  } catch (error) {
    console.error("Error generating chat response:", error)
    throw error
  }
}

/**
 * Fetches the supported file formats from the API
 */
export async function fetchSupportedFormats(): Promise<any> {
  try {
    const response = await fetch(`${API_BASE_URL}/supported-formats`)
    if (!response.ok) {
      throw new Error(`API error: ${response.status}`)
    }
    return await response.json()
  } catch (error) {
    console.error("Error fetching supported formats:", error)
    throw error
  }
}

/**
 * Fetches the API settings
 */
export async function fetchApiSettings(): Promise<any> {
  try {
    const response = await fetch(`${API_BASE_URL}/settings`)
    if (!response.ok) {
      throw new Error(`API error: ${response.status}`)
    }
    return await response.json()
  } catch (error) {
    console.error("Error fetching API settings:", error)
    throw error
  }
}
