"use client"

import { useEffect, useState } from "react"
import { useSearchParams } from "next/navigation"
import Link from "next/link"
import { ArrowLeft, Shield, AlertTriangle, FileCode, Download, PieChart, BarChart, List } from "lucide-react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Progress } from "@/components/ui/progress"
import type { GeneralAnalysisResult } from "@/lib/types"
import { PieChart as RechartsPieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from "recharts"

export default function ScriptAnalysisPage() {
  const searchParams = useSearchParams()
  const encodedData = searchParams.get("data")

  const [loading, setLoading] = useState(true)
  const [data, setData] = useState<GeneralAnalysisResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    try {
      if (encodedData) {
        // Decode and parse the data from the URL
        const decodedData = JSON.parse(decodeURIComponent(encodedData))
        setData(decodedData)
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

  const [isGeneratingReport, setIsGeneratingReport] = useState(false)
  const handleDownloadReport = async () => {
    try {
      if (!data) {
        console.error("No data available for report generation");
        alert("No data available for report generation");
        return;
      }
      
      setIsGeneratingReport(true);
      
      // Create a filename based on the file being analyzed
      const filename = `${data.file_name || 'analysis'}-security-report.pdf`;
      
      // Get fileType from data object if it exists, otherwise use a default value
      const fileType = data.fileType || data.file_type || "unknown";
      
      // Get report ID from data if available, otherwise use a timestamp as fallback
      const reportId = data.id || data.reportId || `report-${Date.now()}`;
      
      // Prepare payload for API - ensure we're sending what the API expects
      const payload = {
        fileData: data,
        fileType: fileType,
        reportId: reportId
      };
      
      // Make the request to generate the PDF
      const response = await fetch("http://localhost:5000/api/generate-report", {
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
      
      // Check content type to ensure we received a PDF
      const contentType = response.headers.get('content-type');
      
      if (contentType?.includes('application/json')) {
        // If we got JSON instead of a PDF, it's probably an error
        const jsonData = await response.json();
        throw new Error(jsonData.error || 'Server returned JSON instead of PDF');
      }
      
      // Get the response as a Blob (PDF file)
      const blob = await response.blob();
      
      if (blob.size === 0) {
        throw new Error("Received empty PDF file");
      }
      
      // Create a download link and trigger the browser's save dialog
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = filename;
      
      document.body.appendChild(link);
      link.click();
      
      // Clean up
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
        <main className="flex-1 flex items-center justify-center">
          <div className="flex flex-col items-center gap-2">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
            <p className="text-muted-foreground">Analyzing script file...</p>
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

  // Prepare data for charts
  const severityCounts = data.indicators.reduce(
    (acc, indicator) => {
      acc[indicator.severity] = (acc[indicator.severity] || 0) + 1
      return acc
    },
    {} as Record<string, number>,
  )

  const pieChartData = [
    { name: "High", value: severityCounts.high || 0 },
    { name: "Medium", value: severityCounts.medium || 0 },
    { name: "Low", value: severityCounts.low || 0 },
  ]

  const SEVERITY_COLORS = ["#ef4444", "#f59e0b", "#3b82f6"]

  return (
    <div className="container py-6">
      <div className="grid gap-6">
        <div className="flex flex-col md:flex-row md:items-center gap-4 justify-between">
          <div>
            <Link href="/" className="flex items-center gap-2 text-muted-foreground hover:text-foreground mb-2">
              <ArrowLeft className="h-4 w-4" />
              <span className="text-sm font-medium">Back to Upload</span>
            </Link>
            <h1 className="text-2xl font-bold tracking-tight mb-1">{data.file_name}</h1>
            <p className="text-muted-foreground">Script File Analysis Report</p>
          </div>
          <div className="flex items-center gap-2">
            {getRiskBadge()}
            <Badge
              variant="outline"
              className="bg-slate-100 border-slate-200 flex gap-1 items-center px-3 py-1.5 shadow-sm"
            >
              <FileCode className="h-3.5 w-3.5" />
              <span>Script File</span>
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

        <Tabs defaultValue="overview" className="w-full">
          <TabsList className="grid w-full grid-cols-3 mb-4">
            <TabsTrigger value="overview">
              <PieChart className="h-4 w-4 mr-2" />
              Overview
            </TabsTrigger>
            <TabsTrigger value="indicators">
              <BarChart className="h-4 w-4 mr-2" />
              Indicators
            </TabsTrigger>
            <TabsTrigger value="mitigations">
              <List className="h-4 w-4 mr-2" />
              Mitigations
            </TabsTrigger>
          </TabsList>

          <TabsContent value="overview">
            <div className="grid md:grid-cols-2 gap-6">
              <Card className="shadow-md">
                <CardHeader>
                  <CardTitle>Risk Assessment</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div>
                      <div className="flex justify-between mb-1">
                        <span className="text-sm font-medium">Overall Risk</span>
                        <span className="text-sm font-medium">{data.confidence}%</span>
                      </div>
                      <Progress
                        value={data.confidence}
                        className={`h-2 ${
                          data.confidence > 75 ? "bg-red-100" : data.confidence > 50 ? "bg-yellow-100" : "bg-green-100"
                        }`}
                        indicatorClassName={`${
                          data.confidence > 75 ? "bg-red-500" : data.confidence > 50 ? "bg-yellow-500" : "bg-green-500"
                        }`}
                      />
                    </div>

                    <div className="pt-4">
                      <h3 className="text-sm font-medium mb-2">Risk Factors</h3>
                      <ul className="space-y-2">
                        {data.indicators.length > 0 ? (
                          data.indicators.map((indicator, index) => (
                            <li key={index} className="flex items-start gap-2">
                              <div
                                className={`rounded-full p-1 ${
                                  indicator.severity === "high"
                                    ? "bg-red-100"
                                    : indicator.severity === "medium"
                                      ? "bg-yellow-100"
                                      : "bg-blue-100"
                                }`}
                              >
                                <AlertTriangle
                                  className={`h-3 w-3 ${
                                    indicator.severity === "high"
                                      ? "text-red-500"
                                      : indicator.severity === "medium"
                                        ? "text-yellow-500"
                                        : "text-blue-500"
                                  }`}
                                />
                              </div>
                              <span className="text-sm">{indicator.type}</span>
                            </li>
                          ))
                        ) : (
                          <li className="text-sm text-muted-foreground">No risk factors identified</li>
                        )}
                      </ul>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card className="shadow-md">
                <CardHeader>
                  <CardTitle>Indicator Severity</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <RechartsPieChart>
                        <Pie
                          data={pieChartData}
                          cx="50%"
                          cy="50%"
                          innerRadius={60}
                          outerRadius={80}
                          fill="#8884d8"
                          paddingAngle={5}
                          dataKey="value"
                          label={({ name, value }) => (value > 0 ? `${name}: ${value}` : "")}
                        >
                          {pieChartData.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={SEVERITY_COLORS[index % SEVERITY_COLORS.length]} />
                          ))}
                        </Pie>
                        <Tooltip />
                        <Legend />
                      </RechartsPieChart>
                    </ResponsiveContainer>
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="indicators">
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
          </TabsContent>

          <TabsContent value="mitigations">
            <Card className="shadow-md">
              <CardHeader>
                <CardTitle>Recommended Mitigations</CardTitle>
              </CardHeader>
              <CardContent>
                {data.mitigations.length > 0 ? (
                  <ul className="space-y-4">
                    {data.mitigations.map((mitigation, index) => (
                      <li key={index} className="flex gap-3 items-start border-b pb-4 last:border-0 last:pb-0">
                        <div className="rounded-full bg-primary/10 p-1.5 mt-0.5">
                          <Shield className="h-4 w-4 text-primary" />
                        </div>
                        <div>
                          <span className="font-medium">Mitigation {index + 1}</span>
                          <p className="text-sm text-muted-foreground mt-1">{mitigation}</p>
                        </div>
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
          </TabsContent>
        </Tabs>
      </div>
    </div>
  )
}
