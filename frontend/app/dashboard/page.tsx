"use client"

import { useState, useEffect } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Button } from "@/components/ui/button"
import { Progress } from "@/components/ui/progress"
import { useRouter } from "next/navigation"
import Link from "next/link"
import { fetchScanHistory } from "@/lib/api"
import {
  BarChart,
  Shield,
  AlertTriangle,
  FileWarning,
  FileSpreadsheet,
  FileIcon,
  FileCode,
  Smartphone,
  Upload,
  Clock,
  ArrowUpRight,
} from "lucide-react"
import { PieChart as RechartsPieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from "recharts"
import { BarChart as RechartsBarChart, Bar, XAxis, YAxis, CartesianGrid } from "recharts"

export default function DashboardPage() {
  const router = useRouter()
  const [scanHistory, setScanHistory] = useState<any[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const loadHistory = async () => {
      try {
        const data = await fetchScanHistory()
        setScanHistory(data)
      } catch (error) {
        console.error("Failed to load history:", error)
      } finally {
        setLoading(false)
      }
    }

    loadHistory()
  }, [])


  // Prepare data for charts
  const fileTypeData = scanHistory.reduce((acc: any, item) => {
    acc[item.fileType] = (acc[item.fileType] || 0) + 1
    return acc
  }, {})

  const pieData = Object.keys(fileTypeData).map((key) => ({
    name: key.toUpperCase(),
    value: fileTypeData[key],
  }))

  const resultData = scanHistory.reduce((acc: any, item) => {
    acc[item.result] = (acc[item.result] || 0) + 1
    return acc
  }, {})

  const barData = Object.keys(resultData).map((key) => ({
    name: key.charAt(0).toUpperCase() + key.slice(1),
    value: resultData[key],
  }))

  const COLORS = ["#0088FE", "#00C49F", "#FFBB28", "#FF8042", "#8884d8"]
  const RESULT_COLORS = {
    clean: "#10b981",
    legitimate: "#10b981",
    suspicious: "#f59e0b",
    malicious: "#ef4444",
  }

  const getFileIcon = (fileType: string) => {
    switch (fileType) {
      case "pe":
        return <FileWarning className="h-5 w-5" />
      case "office":
        return <FileSpreadsheet className="h-5 w-5" />
      case "pdf":
        return <FileIcon className="h-5 w-5" />
      case "script":
        return <FileCode className="h-5 w-5" />
      case "apk":
        return <Smartphone className="h-5 w-5" />
      default:
        return <FileIcon className="h-5 w-5" />
    }
  }

  const formatDate = (dateString: string) => {
    const date = new Date(dateString)
    return new Intl.DateTimeFormat("en-US", {
      year: "numeric",
      month: "short",
      day: "numeric",
    }).format(date)
  }

  return (
    <div className="container py-8">
      <div className="flex flex-col gap-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold tracking-tight mb-2">Dashboard</h1>
            <p className="text-muted-foreground">
              Welcome back, User! Here's an overview of your security status.
            </p>
          </div>
          <Button asChild>
            <Link href="/">
              <Upload className="mr-2 h-4 w-4" />
              Scan New File
            </Link>
          </Button>
        </div>

        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <Card className="shadow-md">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Total Scans</CardTitle>
              <Shield className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{scanHistory.length}</div>
              <p className="text-xs text-muted-foreground">+{Math.min(scanHistory.length, 5)} in the last 7 days</p>
            </CardContent>
          </Card>
          <Card className="shadow-md">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Threats Detected</CardTitle>
              <AlertTriangle className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">
                {scanHistory.reduce((acc, item) => acc + (item.threatCount || 0), 0)}
              </div>
              <p className="text-xs text-muted-foreground">Across all scanned files</p>
            </CardContent>
          </Card>
          <Card className="shadow-md">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Average Risk Score</CardTitle>
              <BarChart className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">
                {scanHistory.length > 0
                  ? Math.round(scanHistory.reduce((acc, item) => acc + (item.riskScore || 0), 0) / scanHistory.length)
                  : 0}
                %
              </div>
              <Progress
                value={
                  scanHistory.length > 0
                    ? scanHistory.reduce((acc, item) => acc + (item.riskScore || 0), 0) / scanHistory.length
                    : 0
                }
                className="h-2 mt-2"
              />
            </CardContent>
          </Card>
          <Card className="shadow-md">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Last Scan</CardTitle>
              <Clock className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">
                {scanHistory.length > 0 ? formatDate(scanHistory[0].scanDate) : "N/A"}
              </div>
              <p className="text-xs text-muted-foreground">
                {scanHistory.length > 0 ? scanHistory[0].fileName : "No scans yet"}
              </p>
            </CardContent>
          </Card>
        </div>

        <Tabs defaultValue="overview" className="w-full">
          <TabsList className="grid w-full max-w-md grid-cols-2">
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="recent">Recent Scans</TabsTrigger>
          </TabsList>
          <TabsContent value="overview" className="mt-6">
            <div className="grid gap-6 md:grid-cols-2">
              <Card className="shadow-md">
                <CardHeader>
                  <CardTitle>File Types Distribution</CardTitle>
                  <CardDescription>Breakdown of scanned file types</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="h-80">
                    {scanHistory.length > 0 ? (
                      <ResponsiveContainer width="100%" height="100%">
                        <RechartsPieChart>
                          <Pie
                            data={pieData}
                            cx="50%"
                            cy="50%"
                            labelLine={false}
                            outerRadius={80}
                            fill="#8884d8"
                            dataKey="value"
                            label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                          >
                            {pieData.map((entry, index) => (
                              <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                            ))}
                          </Pie>
                          <Tooltip />
                          <Legend />
                        </RechartsPieChart>
                      </ResponsiveContainer>
                    ) : (
                      <div className="flex items-center justify-center h-full">
                        <p className="text-muted-foreground">No data available</p>
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>
              <Card className="shadow-md">
                <CardHeader>
                  <CardTitle>Scan Results</CardTitle>
                  <CardDescription>Distribution of scan outcomes</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="h-80">
                    {scanHistory.length > 0 ? (
                      <ResponsiveContainer width="100%" height="100%">
                        <RechartsBarChart data={barData} layout="vertical" margin={{ left: 80 }}>
                          <CartesianGrid strokeDasharray="3 3" />
                          <XAxis type="number" />
                          <YAxis type="category" dataKey="name" />
                          <Tooltip />
                          <Bar dataKey="value" name="Count">
                            {barData.map((entry, index) => (
                              <Cell
                                key={`cell-${index}`}
                                fill={
                                  RESULT_COLORS[entry.name.toLowerCase() as keyof typeof RESULT_COLORS] || COLORS[0]
                                }
                              />
                            ))}
                          </Bar>
                        </RechartsBarChart>
                      </ResponsiveContainer>
                    ) : (
                      <div className="flex items-center justify-center h-full">
                        <p className="text-muted-foreground">No data available</p>
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>
          <TabsContent value="recent" className="mt-6">
            <Card className="shadow-md">
              <CardHeader>
                <CardTitle>Recent Scan Activity</CardTitle>
                <CardDescription>Your most recent file analysis results</CardDescription>
              </CardHeader>
              <CardContent>
                {loading ? (
                  <div className="flex justify-center py-12">
                    <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
                  </div>
                ) : scanHistory.length > 0 ? (
                  <div className="space-y-4">
                    {scanHistory.slice(0, 5).map((item, index) => (
                      <div
                        key={index}
                        className="flex items-center justify-between border-b pb-4 last:border-0 last:pb-0"
                      >
                        <div className="flex items-center gap-3">
                          <div className="rounded-full bg-primary/10 p-2">{getFileIcon(item.fileType)}</div>
                          <div>
                            <h4 className="font-medium">{item.fileName}</h4>
                            <div className="flex items-center gap-2 text-sm text-muted-foreground">
                              <span>{formatDate(item.scanDate)}</span>
                              <span>•</span>
                              <span className="capitalize">{item.fileType}</span>
                            </div>
                          </div>
                        </div>
                        <div className="flex items-center gap-3">
                          <div className="text-right">
                            <div
                              className={`text-sm font-medium ${
                                item.result === "malicious"
                                  ? "text-red-600"
                                  : item.result === "suspicious"
                                    ? "text-yellow-600"
                                    : "text-green-600"
                              }`}
                            >
                              {item.result.charAt(0).toUpperCase() + item.result.slice(1)}
                            </div>
                            <div className="text-sm text-muted-foreground">Risk: {item.riskScore}%</div>
                          </div>
                          <Button variant="ghost" size="icon" asChild>
                            <Link href={`/analysis/${item.fileType}?id=${item.id}`}>
                              <ArrowUpRight className="h-4 w-4" />
                            </Link>
                          </Button>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-12">
                    <Shield className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                    <h3 className="text-lg font-medium mb-2">No scan history yet</h3>
                    <p className="text-muted-foreground mb-4">Upload a file to get started with malware analysis</p>
                    <Button asChild>
                      <Link href="/">
                        <Upload className="mr-2 h-4 w-4" />
                        Scan Your First File
                      </Link>
                    </Button>
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
