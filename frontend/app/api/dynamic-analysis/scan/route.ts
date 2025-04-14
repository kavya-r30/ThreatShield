import { NextResponse } from "next/server"

export async function POST(req: Request) {
  try {
    const formData = await req.formData()
    const file = formData.get("file") as File
    const apiKey = (formData.get("api_key") as string) || process.env.NEXT_PUBLIC_VIRUSTOTAL_API_KEY

    if (!file) {
      return NextResponse.json({ error: "No file provided" }, { status: 400 })
    }

    // Create a new FormData to send to the backend API
    const apiFormData = new FormData()
    apiFormData.append("file", file)

    // Get the API base URL from environment variables
    const apiBaseUrl = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:5000/api"

    // Call the backend API to analyze the file
    const response = await fetch(`${apiBaseUrl}/analyze-dynamic`, {
      method: "POST",
      body: apiFormData,
    })

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({ error: "Unknown error" }))
      throw new Error(errorData.error || `API error: ${response.status}`)
    }

    // Get the analysis results
    const analysisResults = await response.json()

    // Process the results to make them more usable in the frontend
    const processedResults = processAnalysisResults(analysisResults)

    return NextResponse.json(processedResults)
  } catch (error) {
    console.error("Error in dynamic analysis scan:", error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "Failed to analyze file" },
      { status: 500 },
    )
  }
}

function processAnalysisResults(results: any) {
  // Extract the most important information from the analysis results
  const fileInfo = results.file_info || {}
  const dynamicAnalysis = results.dynamic_analysis?.data || []
  const staticAnalysis = results.static_analysis?.data?.attributes || {}
  const report = results.report || ""

  // Create a summary of the analysis
  const summary = {
    file_info: {
      name: fileInfo.name || "Unknown",
      size: fileInfo.size || 0,
      type: staticAnalysis.type_description || "Unknown",
      sha256: fileInfo.hashes?.sha256 || "",
      md5: fileInfo.hashes?.md5 || "",
      first_seen: staticAnalysis.first_submission_date || 0,
      last_seen: staticAnalysis.last_analysis_date || 0,
    },
    scan_results: {
      total_engines:
        staticAnalysis.last_analysis_stats?.undetected + staticAnalysis.last_analysis_stats?.malicious || 0,
      malicious: staticAnalysis.last_analysis_stats?.malicious || 0,
      suspicious: staticAnalysis.last_analysis_stats?.suspicious || 0,
      detection_rate: calculateDetectionRate(staticAnalysis.last_analysis_stats),
      detections: extractDetections(staticAnalysis.last_analysis_results),
    },
    detailed_results: staticAnalysis.last_analysis_results || {},
    dynamic_analysis: {
      behaviors: dynamicAnalysis.map((behavior: any) => ({
        sandbox_name: behavior.attributes?.sandbox_name || "Unknown",
        processes_created: behavior.attributes?.processes_created || [],
        files_dropped: behavior.attributes?.files_dropped || [],
        registry_keys_opened: behavior.attributes?.registry_keys_opened?.slice(0, 20) || [],
        network_connections: behavior.attributes?.ip_traffic || [],
        mitre_techniques: behavior.attributes?.mitre_attack_techniques || [],
        signatures: behavior.attributes?.signature_matches || [],
      })),
    },
    report: report,
  }

  return summary
}

function calculateDetectionRate(stats: any) {
  if (!stats) return "0%"

  const total = (stats.malicious || 0) + (stats.suspicious || 0) + (stats.undetected || 0)
  if (total === 0) return "0%"

  const rate = (((stats.malicious || 0) + (stats.suspicious || 0)) / total) * 100
  return `${rate.toFixed(2)}%`
}

function extractDetections(results: any) {
  if (!results) return []

  const detections = []
  for (const [engine, result] of Object.entries(results)) {
    if ((result as any).category === "malicious" || (result as any).category === "suspicious") {
      detections.push({
        engine,
        category: (result as any).category,
        result: (result as any).result || "Unknown",
      })
    }
  }

  return detections
}
