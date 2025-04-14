import { NextResponse } from "next/server"
import { FileType } from "@/lib/types"
import { mockPEAnalysisResult } from "@/lib/mock-data"

export async function POST(req: Request) {
  try {
    const formData = await req.formData()
    const file = formData.get("file") as File
    const fileType = formData.get("fileType") as FileType

    if (!file) {
      return NextResponse.json({ error: "No file provided" }, { status: 400 })
    }

    // In a real implementation, we would process the file based on its type
    // For demo purposes, we'll return mock data

    // Generate a unique ID for the scan
    const scanId = `scan-${Date.now()}`

    // Return different mock data based on file type
    switch (fileType) {
      case FileType.PE:
        return NextResponse.json({
          id: scanId,
          result: mockPEAnalysisResult,
        })

      case FileType.OFFICE:
        return NextResponse.json({
          id: scanId,
          result: {
            summary: {
              prediction: "clean",
              confidence_score: 92.3,
              threat_summary: "No threats detected in this Office document.",
            },
            // Add more mock data as needed
          },
        })

      case FileType.PDF:
        return NextResponse.json({
          id: scanId,
          result: {
            summary: {
              prediction: "suspicious",
              confidence_score: 68.5,
              threat_summary: "Potentially suspicious JavaScript detected in PDF.",
            },
            // Add more mock data as needed
          },
        })

      case FileType.SCRIPT:
        return NextResponse.json({
          id: scanId,
          result: {
            summary: {
              prediction: "malicious",
              confidence_score: 89.7,
              threat_summary: "Malicious PowerShell commands detected.",
            },
            // Add more mock data as needed
          },
        })

      default:
        return NextResponse.json({ error: "Unsupported file type" }, { status: 400 })
    }
  } catch (error) {
    console.error("Error in analyze route:", error)
    return NextResponse.json({ error: "Failed to process your request" }, { status: 500 })
  }
}
