"use client"

import { useEffect, useState } from "react"
import { useSearchParams } from "next/navigation"
import Link from "next/link"
import { ArrowLeft, Shield, AlertTriangle, FileWarning, Download } from "lucide-react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import type { PEAnalysisResult } from "@/lib/types"
import SummaryTab from "@/components/analysis/summary-tab"
import FeaturesTab from "@/components/analysis/features-tab"
import DetailedAnalysisTab from "@/components/analysis/detailed-analysis-tab"

export default function PEAnalysisPage() {
  const searchParams = useSearchParams()
  const encodedData = searchParams.get("data")

  const [loading, setLoading] = useState(true)
  const [data, setData] = useState<PEAnalysisResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    try {
      if (encodedData) {
        // Decode and parse the data from the URL
        const decodedData = JSON.parse(decodeURIComponent(encodedData))
        setData({
          filename: decodedData.filename,
          analysis_data: decodedData.analysis_data,
        })
      } else {
        setError("No analysis data provided")
      }
    } catch (err) {
      console.error("Error parsing analysis data:", err)
      setError("Failed to parse analysis data")
    } finally {
      setLoading(false)
    }
  }, [encodedData])

  if (loading) {
    return (
      <div className="flex min-h-screen flex-col">
        <main className="flex-1 flex items-center justify-center">
          <div className="flex flex-col items-center gap-2">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
            <p className="text-muted-foreground">Analyzing file...</p>
          </div>
        </main>
      </div>
    )
  }

  if (error || !data) {
    return (
      <div className="flex min-h-screen flex-col">
        <main className="flex-1 flex items-center justify-center">
          <div className="flex flex-col items-center gap-2 text-center max-w-md">
            <AlertTriangle className="h-12 w-12 text-destructive" />
            <h2 className="text-xl font-bold">Error Loading Analysis</h2>
            <p className="text-muted-foreground">{error || "An unknown error occurred"}</p>
            <Button asChild className="mt-4">
              <Link href="/">Return to Home</Link>
            </Button>
          </div>
        </main>
      </div>
    )
  }

  const { analysis_data, filename } = data
  const { summary, risk_metrics } = analysis_data
  const isClean = summary.prediction !== "malicious"

  return (
    <div className="container py-6">
      <div className="grid gap-6">
        <div className="flex flex-col md:flex-row md:items-center gap-4 justify-between">
          <div>
            <Link href="/" className="flex items-center gap-2 text-muted-foreground hover:text-foreground mb-2">
              <ArrowLeft className="h-4 w-4" />
              <span className="text-sm font-medium">Back to Upload</span>
            </Link>
            <h1 className="text-2xl font-bold tracking-tight mb-1">{filename}</h1>
            <p className="text-muted-foreground">PE File Analysis Report</p>
          </div>
          <div className="flex items-center gap-2">
            {isClean ? (
              <Badge
                variant="outline"
                className="bg-green-50 text-green-700 border-green-200 flex gap-1 items-center px-3 py-1.5 shadow-sm"
              >
                <Shield className="h-4 w-4" />
                <span>Clean</span>
              </Badge>
            ) : (
              <Badge
                variant="outline"
                className="bg-red-50 text-red-700 border-red-200 flex gap-1 items-center px-3 py-1.5 shadow-sm"
              >
                <AlertTriangle className="h-4 w-4" />
                <span>Malicious</span>
              </Badge>
            )}
            <Badge
              variant="outline"
              className="bg-slate-100 border-slate-200 flex gap-1 items-center px-3 py-1.5 shadow-sm"
            >
              <FileWarning className="h-3.5 w-3.5" />
              <span>PE File</span>
            </Badge>
            <Button variant="outline" size="sm" className="gap-1.5">
              <Download className="h-4 w-4" />
              <span>Report</span>
            </Button>
          </div>
        </div>

        <Card
          className={`border-l-4 shadow-md ${risk_metrics.risk_level === "high" ? "border-l-red-500" : risk_metrics.risk_level === "medium" ? "border-l-yellow-500" : "border-l-green-500"}`}
        >
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2">
              <span>Threat Analysis Summary</span>
              <Badge
                className={`${
                  risk_metrics.risk_level === "high"
                    ? "bg-red-100 text-red-800 hover:bg-red-100"
                    : risk_metrics.risk_level === "medium"
                      ? "bg-yellow-100 text-yellow-800 hover:bg-yellow-100"
                      : "bg-green-100 text-green-800 hover:bg-green-100"
                }`}
              >
                {risk_metrics.risk_level === "high"
                  ? "High Risk"
                  : risk_metrics.risk_level === "medium"
                    ? "Medium Risk"
                    : "Low Risk"}
              </Badge>
            </CardTitle>
            <CardDescription>{summary.threat_summary}</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-2">
              <div className="flex flex-col">
                <span className="text-sm text-muted-foreground">Risk Score</span>
                <span className="text-2xl font-bold">{risk_metrics.risk_score}%</span>
              </div>
              <div className="flex flex-col">
                <span className="text-sm text-muted-foreground">Confidence</span>
                <span className="text-2xl font-bold">{summary.confidence_score}%</span>
              </div>
              <div className="flex flex-col">
                <span className="text-sm text-muted-foreground">Suspicious Features</span>
                <span className="text-2xl font-bold">{risk_metrics.total_suspicious_features}</span>
              </div>
              <div className="flex flex-col">
                <span className="text-sm text-muted-foreground">High-Risk Features</span>
                <span className="text-2xl font-bold">{risk_metrics.high_risk_features}</span>
              </div>
            </div>
          </CardContent>
        </Card>

        <Tabs defaultValue="summary" className="w-full">
          <TabsList className="grid w-full grid-cols-3 mb-4">
            <TabsTrigger value="summary">Summary</TabsTrigger>
            <TabsTrigger value="features">Key Features</TabsTrigger>
            <TabsTrigger value="detailed">Detailed Analysis</TabsTrigger>
          </TabsList>
          <TabsContent value="summary">
            <SummaryTab data={data} />
          </TabsContent>
          <TabsContent value="features">
            <FeaturesTab data={data} />
          </TabsContent>
          <TabsContent value="detailed">
            <DetailedAnalysisTab data={data} />
          </TabsContent>
        </Tabs>
      </div>
    </div>
  )
}
