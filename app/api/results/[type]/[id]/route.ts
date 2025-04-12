import { NextResponse } from "next/server"
import { FileType } from "@/lib/types"
import { mockPEAnalysisResult } from "@/lib/mock-data"

export async function GET(req: Request, { params }: { params: { type: string; id: string } }) {
  try {
    const { type, id } = params

    // Validate the file type
    if (!Object.values(FileType).includes(type as FileType)) {
      return NextResponse.json({ error: "Invalid file type" }, { status: 400 })
    }

    // In a real implementation, we would fetch the results from a database
    // For demo purposes, we'll return mock data based on the file type

    switch (type) {
      case FileType.PE:
        return NextResponse.json(mockPEAnalysisResult)

      case FileType.OFFICE:
        return NextResponse.json({
          summary: {
            prediction: "clean",
            prediction_code: 0,
            confidence_score: 92.3,
            confidence_distribution: {
              legitimate: 92.3,
              malicious: 7.7,
            },
            threat_summary: "No threats detected in this Office document.",
          },
          risk_metrics: {
            total_suspicious_features: 0,
            high_risk_features: 0,
            medium_risk_features: 0,
            low_risk_features: 0,
            risk_score: 8,
            risk_level: "low",
          },
          // Add more mock data as needed
        })

      case FileType.PDF:
        return NextResponse.json({
          summary: {
            prediction: "suspicious",
            prediction_code: 2,
            confidence_score: 68.5,
            confidence_distribution: {
              legitimate: 31.5,
              malicious: 68.5,
            },
            threat_summary: "Potentially suspicious JavaScript detected in PDF.",
          },
          risk_metrics: {
            total_suspicious_features: 2,
            high_risk_features: 0,
            medium_risk_features: 2,
            low_risk_features: 0,
            risk_score: 45,
            risk_level: "medium",
          },
          // Add more mock data as needed
        })

      case FileType.SCRIPT:
        return NextResponse.json({
          summary: {
            prediction: "malicious",
            prediction_code: 1,
            confidence_score: 89.7,
            confidence_distribution: {
              legitimate: 10.3,
              malicious: 89.7,
            },
            threat_summary: "Malicious PowerShell commands detected.",
          },
          risk_metrics: {
            total_suspicious_features: 3,
            high_risk_features: 2,
            medium_risk_features: 1,
            low_risk_features: 0,
            risk_score: 88,
            risk_level: "high",
          },
          // Add more mock data as needed
        })

      default:
        return NextResponse.json({ error: "Unsupported file type" }, { status: 400 })
    }
  } catch (error) {
    console.error("Error in results route:", error)
    return NextResponse.json({ error: "Failed to retrieve results" }, { status: 500 })
  }
}
