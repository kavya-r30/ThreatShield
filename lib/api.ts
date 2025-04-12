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
    console.log("API Response:", result)

    // Return the result directly without generating an ID or saving to history
    return result
  } catch (error) {
    console.error("Error uploading file:", error)
    throw error
  }
}

/**
 * Fetches analysis results for a specific file
 * This is a placeholder since the backend doesn't have a /results endpoint
 * In a real implementation, you would store the analysis result in a database
 * and fetch it using an ID
 */
export async function fetchAnalysisResult(
  result: any,
  fileType: string,
): Promise<PEAnalysisResult | GeneralAnalysisResult> {
  // For PE files, return the result directly
  if (fileType === FileType.PE) {
    return {
      filename: result.filename,
      analysis_data: result.analysis_data,
    } as PEAnalysisResult
  }

  // For other file types, return the result directly
  return result as GeneralAnalysisResult
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
