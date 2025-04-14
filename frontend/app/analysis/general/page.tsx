"use client"

import { useEffect, useState } from "react"
import { useSearchParams } from "next/navigation"
import Link from "next/link"
import {
  ArrowLeft,
  Shield,
  AlertTriangle,
  FileWarning,
  Download,
  FileSpreadsheet,
  FileIcon,
  FileCode,
  Smartphone,
} from "lucide-react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Separator } from "@/components/ui/separator"
import { FileType, type GeneralAnalysisResult } from "@/lib/types"
import { fetchAnalysisResult } from "@/lib/api"

export default function GeneralAnalysisPage() {
  const searchParams = useSearchParams()
  const id = searchParams.get("id")
  const fileType = searchParams.get("type") as FileType

  const [loading, setLoading] = useState(true)
  const [data, setData] = useState<GeneralAnalysisResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [isGeneratingReport, setIsGeneratingReport] = useState(false)
  const [debugInfo, setDebugInfo] = useState<string[]>([])

  // Function to add debug information
  const addDebugInfo = (info: string) => {
    console.log(info);
    setDebugInfo(prev => [...prev, `${new Date().toISOString()}: ${info}`]);
  }

  useEffect(() => {
    const loadData = async () => {
      try {
        if (id && fileType) {
          // Fetch the analysis result from the API
          const result = await fetchAnalysisResult(id, fileType)
          setData(result as GeneralAnalysisResult)
        } else {
          setError("No analysis ID or file type provided")
        }
      } catch (err) {
        console.error("Error loading analysis data:", err)
        setError("Failed to load analysis data")
      } finally {
        setLoading(false)
      }
    }

    loadData()
  }, [id, fileType])

  const handleDownloadReport = async () => {
    try {
      if (!data) {
        console.error("No data available for report generation");
        alert("No data available for report generation");
        return;
      }
      
      setIsGeneratingReport(true);
      
      const filename = `${data.file_name || 'analysis'}-security-report.pdf`;
      
      const fileType = data.fileType || data.file_type || "unknown";
      
      const reportId = data.id || data.reportId || `report-${Date.now()}`;
      
      const payload = {
        fileData: data,
        fileType: fileType,
        reportId: reportId
      };
      
      const response = await fetch(`${process.env.NEXT_PUBLIC_API_BASE_URL}/generate-report`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      });      
      
      if (!response.ok) {
        let errorMessage = `Server responded with status ${response.status}`;
        try {
          const errorData = await response.json();
          errorMessage = errorData.error || errorData.message || errorMessage;
        } catch (e) {
          console.error("Could not parse error response as JSON:", e);
        }
        throw new Error(errorMessage);
      }
      
      const contentType = response.headers.get('content-type');
      
      if (contentType?.includes('application/json')) {
        const jsonData = await response.json();
        throw new Error(jsonData.error || 'Server returned JSON instead of PDF');
      }
      
      const blob = await response.blob();
      
      if (blob.size === 0) {
        throw new Error("Received empty PDF file");
      }
      
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = filename;
      
      document.body.appendChild(link);
      link.click();
      
      setTimeout(() => {
        document.body.removeChild(link);
        window.URL.revokeObjectURL(url);
      }, 100);
      
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err);
      console.error("Error generating report:", errorMessage);
      alert(`An error occurred while generating the report: ${errorMessage}`);
    } finally {
      setIsGeneratingReport(false);
    }
  }

  if (loading) {
    return (
      <div className="flex min-h-screen flex-col">
        <header className="sticky top-0 z-10 border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
          <div className="container flex h-16 items-center">
            <Link href="/" className="flex items-center gap-2">
              <ArrowLeft className="h-4 w-4" />
              <span className="text-sm font-medium">Back</span>
            </Link>
          </div>
        </header>
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
        <header className="sticky top-0 z-10 border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
          <div className="container flex h-16 items-center">
            <Link href="/" className="flex items-center gap-2">
              <ArrowLeft className="h-4 w-4" />
              <span className="text-sm font-medium">Back</span>
            </Link>
          </div>
        </header>
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

  const getFileTypeIcon = () => {
    switch (fileType) {
      case FileType.OFFICE:
        return <FileSpreadsheet className="h-3.5 w-3.5" />
      case FileType.PDF:
        return <FileIcon className="h-3.5 w-3.5" />
      case FileType.SCRIPT:
        return <FileCode className="h-3.5 w-3.5" />
      case FileType.APK:
        return <Smartphone className="h-3.5 w-3.5" />
      default:
        return <FileWarning className="h-3.5 w-3.5" />
    }
  }

  const getFileTypeName = () => {
    switch (fileType) {
      case FileType.OFFICE:
        return "Office Document"
      case FileType.PDF:
        return "PDF File"
      case FileType.SCRIPT:
        return "Script File"
      case FileType.APK:
        return "Android APK"
      default:
        return "Unknown File"
    }
  }

  const getRiskBadge = () => {
    switch (data.risk_level) {
      case "critical":
        return (
          <Badge
            variant="outline"
            className="bg-purple-50 text-purple-700 border-purple-200 flex gap-1 items-center px-3 py-1.5 shadow-sm"
          >
            <AlertTriangle className="h-4 w-4" />
            <span>Critical Risk</span>
          </Badge>
        )
      case "high":
        return (
          <Badge
            variant="outline"
            className="bg-red-50 text-red-700 border-red-200 flex gap-1 items-center px-3 py-1.5 shadow-sm"
          >
            <AlertTriangle className="h-4 w-4" />
            <span>High Risk</span>
          </Badge>
        )
      case "medium":
        return (
          <Badge
            variant="outline"
            className="bg-yellow-50 text-yellow-700 border-yellow-200 flex gap-1 items-center px-3 py-1.5 shadow-sm"
          >
            <AlertTriangle className="h-4 w-4" />
            <span>Medium Risk</span>
          </Badge>
        )
      default:
        return (
          <Badge
            variant="outline"
            className="bg-green-50 text-green-700 border-green-200 flex gap-1 items-center px-3 py-1.5 shadow-sm"
          >
            <Shield className="h-4 w-4" />
            <span>Low Risk</span>
          </Badge>
        )
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "high":
        return "text-red-600 bg-red-50 border-red-200"
      case "medium":
        return "text-yellow-600 bg-yellow-50 border-yellow-200"
      case "low":
        return "text-blue-600 bg-blue-50 border-blue-200"
      default:
        return "text-slate-600 bg-slate-50 border-slate-200"
    }
  }

  return (
    <div className="flex min-h-screen flex-col bg-slate-50 dark:bg-slate-950/30">
      <header className="sticky top-0 z-10 border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="container flex h-16 items-center">
          <Link href="/" className="flex items-center gap-2">
            <ArrowLeft className="h-4 w-4" />
            <span className="text-sm font-medium">Back to Upload</span>
          </Link>
        </div>
      </header>
      <main className="flex-1 container py-6">
        <div className="grid gap-6">
          <div className="flex flex-col md:flex-row md:items-center gap-4 justify-between">
            <div>
              <h1 className="text-2xl font-bold tracking-tight mb-1">{data.file_name}</h1>
              <p className="text-muted-foreground">{getFileTypeName()} Analysis Report</p>
            </div>
            <div className="flex items-center gap-2">
              {getRiskBadge()}
              <Badge
                variant="outline"
                className="bg-slate-100 border-slate-200 flex gap-1 items-center px-3 py-1.5 shadow-sm"
              >
                {getFileTypeIcon()}
                <span>{getFileTypeName()}</span>
              </Badge>
              <Button 
              variant="outline" 
              size="sm" 
              className="gap-1.5" 
              onClick={handleDownloadReport}
              disabled={isGeneratingReport}
            >
              {isGeneratingReport ? (
                <>
                  <div className="h-4 w-4 animate-spin rounded-full border-2 border-primary border-t-transparent"></div>
                  <span>Generating...</span>
                </>
              ) : (
                <>
                  <Download className="h-4 w-4" />
                  <span>Report</span>
                </>
              )}
            </Button>
            </div>
          </div>

          <Card
            className={`border-l-4 shadow-md ${
              data.risk_level === "critical"
                ? "border-l-purple-500"
                : data.risk_level === "high"
                  ? "border-l-red-500"
                  : data.risk_level === "medium"
                    ? "border-l-yellow-500"
                    : "border-l-green-500"
            }`}
          >
            <CardHeader className="pb-2">
              <CardTitle className="flex items-center gap-2">
                <span>Analysis Summary</span>
                <Badge
                  className={`${
                    data.risk_level === "critical"
                      ? "bg-purple-100 text-purple-800"
                      : data.risk_level === "high"
                        ? "bg-red-100 text-red-800"
                        : data.risk_level === "medium"
                          ? "bg-yellow-100 text-yellow-800"
                          : "bg-green-100 text-green-800"
                  }`}
                >
                  {data.is_malicious ? "Malicious" : "Clean"}
                </Badge>
              </CardTitle>
              <CardDescription>{data.analysis_summary}</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-4 mt-2">
                <div className="flex flex-col">
                  <span className="text-sm text-muted-foreground">Confidence</span>
                  <span className="text-2xl font-bold">{data.confidence}%</span>
                </div>
                <div className="flex flex-col">
                  <span className="text-sm text-muted-foreground">Risk Level</span>
                  <span className="text-2xl font-bold capitalize">{data.risk_level}</span>
                </div>
                <div className="flex flex-col">
                  <span className="text-sm text-muted-foreground">Indicators</span>
                  <span className="text-2xl font-bold">{data.indicators.length}</span>
                </div>
              </div>
            </CardContent>
          </Card>

          <div className="grid md:grid-cols-2 gap-6">
            <Card className="shadow-md">
              <CardHeader>
                <CardTitle>Threat Indicators</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {data.indicators.length > 0 ? (
                    data.indicators.map((indicator, index) => (
                      <div key={index} className="border rounded-lg p-4">
                        <div className="flex justify-between items-start mb-2">
                          <h3 className="font-medium">{indicator.type}</h3>
                          <Badge className={getSeverityColor(indicator.severity)}>
                            {indicator.severity.charAt(0).toUpperCase() + indicator.severity.slice(1)} Severity
                          </Badge>
                        </div>
                        <p className="text-sm text-muted-foreground">{indicator.details}</p>
                      </div>
                    ))
                  ) : (
                    <div className="text-center py-6">
                      <Shield className="h-12 w-12 text-green-500 mx-auto mb-2" />
                      <h3 className="font-medium text-lg">No Threat Indicators Found</h3>
                      <p className="text-sm text-muted-foreground">This file appears to be clean.</p>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>

            <Card className="shadow-md">
              <CardHeader>
                <CardTitle>Recommended Mitigations</CardTitle>
              </CardHeader>
              <CardContent>
                {data.mitigations.length > 0 ? (
                  <ul className="space-y-2">
                    {data.mitigations.map((mitigation, index) => (
                      <li key={index} className="flex gap-2 items-start">
                        <div className="rounded-full bg-primary/10 p-1 mt-0.5">
                          <Shield className="h-4 w-4 text-primary" />
                        </div>
                        <span>{mitigation}</span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <div className="text-center py-6">
                    <Shield className="h-12 w-12 text-green-500 mx-auto mb-2" />
                    <h3 className="font-medium text-lg">No Mitigations Needed</h3>
                    <p className="text-sm text-muted-foreground">This file appears to be safe to use.</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          <Card className="shadow-md">
            <CardHeader>
              <CardTitle>AI Analysis</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="whitespace-pre-line">{data.analysis_summary}</p>
              <Separator className="my-4" />
              <div className="flex justify-end">
                <Button variant="outline" asChild>
                  <Link href="/chatbot">Ask AI for More Details</Link>
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      </main>
    </div>
  )
}