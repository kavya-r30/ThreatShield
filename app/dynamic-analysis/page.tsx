"use client"

import type React from "react"

import { useState, useRef, useEffect } from "react"
import Link from "next/link"
import {
  ArrowLeft,
  Shield,
  AlertTriangle,
  Upload,
  Download,
  FileText,
  Trash2,
  ExternalLink,
  Activity,
  Database,
  Network,
  ComputerIcon as Registry,
} from "lucide-react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle, CardFooter } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Progress } from "@/components/ui/progress"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { ScrollArea } from "@/components/ui/scroll-area"
import { PieChart, BarChart } from "@/components/charts"

interface ScanResult {
  file_info: {
    name: string
    size: number
    type: string
    sha256: string
    md5: string
    first_seen: number
    last_seen: number
  }
  scan_results: {
    total_engines: number
    malicious: number
    suspicious: number
    detection_rate: string
    detections: Array<{
      engine: string
      category: string
      result: string
    }>
  }
  detailed_results: Record<
    string,
    {
      category: string
      result: string
      engine_name: string
      engine_version: string
    }
  >
  dynamic_analysis: {
    behaviors: Array<{
      sandbox_name: string
      processes_created: string[]
      files_dropped: Array<{
        path: string
        sha256: string
        type?: string
      }>
      registry_keys_opened: string[]
      network_connections: Array<{
        destination_ip: string
        destination_port: number
        transport_layer_protocol: string
      }>
      mitre_techniques: Array<{
        id: string
        signature_description?: string
        severity?: string
      }>
      signatures: Array<{
        id: string
        name?: string
        description?: string
        severity?: string
        match_data?: string[]
      }>
    }>
  }
  report: string
}

interface ScanHistoryItem {
  name: string
  result: string
  full_result: ScanResult
}

export default function DynamicAnalysisPage() {
  const [apiKey, setApiKey] = useState<string>(process.env.NEXT_PUBLIC_VIRUSTOTAL_API_KEY || "7393cd0b58277c7af0020bad0fe95d531ba723dfa2035b110f6a1922c21bd090")
  const [file, setFile] = useState<File | null>(null)
  const [scanning, setScanning] = useState<boolean>(false)
  const [scanCompleted, setScanCompleted] = useState<boolean>(false)
  const [currentResult, setCurrentResult] = useState<ScanResult | null>(null)
  const [scanHistory, setScanHistory] = useState<ScanHistoryItem[]>([])
  const [progress, setProgress] = useState<number>(0)
  const [statusMessage, setStatusMessage] = useState<string>("")
  const [selectedCategory, setSelectedCategory] = useState<string>("All")
  const [activeTab, setActiveTab] = useState<string>("overview")
  const [activeBehaviorTab, setActiveBehaviorTab] = useState<string>("processes")
  const fileInputRef = useRef<HTMLInputElement>(null)

  // Load scan history from localStorage on component mount
  useEffect(() => {
    const savedHistory = localStorage.getItem("vtScanHistory")
    if (savedHistory) {
      try {
        setScanHistory(JSON.parse(savedHistory))
      } catch (error) {
        console.error("Error loading scan history:", error)
      }
    }
  }, [])

  // Save scan history to localStorage when it changes
  useEffect(() => {
    localStorage.setItem("vtScanHistory", JSON.stringify(scanHistory))
  }, [scanHistory])

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      setFile(e.target.files[0])
      setScanCompleted(false)
    }
  }

  const handleScan = async () => {
    if (!file || scanning) return

    setScanning(true)
    setProgress(0)
    setStatusMessage("Preparing to scan...")
    setScanCompleted(false)

    try {
      // Create FormData for file upload
      const formData = new FormData()
      formData.append("file", file)
      formData.append("api_key", apiKey)

      // Simulate progress updates
      const progressInterval = setInterval(() => {
        setProgress((prev) => {
          if (prev >= 90) {
            clearInterval(progressInterval)
            return 90
          }
          return prev + 5
        })
      }, 1000)

      // Call the API to scan the file
      const response = await fetch("/api/dynamic-analysis/scan", {
        method: "POST",
        body: formData,
      })

      clearInterval(progressInterval)

      if (!response.ok) {
        const errorData = await response.json()
        throw new Error(errorData.error || "Failed to scan file")
      }

      const result: ScanResult = await response.json()
      setProgress(100)
      setStatusMessage("Scan complete!")

      // Determine risk level
      const detectionRate = result.scan_results.detection_rate
      const rateValue = Number.parseFloat(detectionRate.replace("%", "")) || 0
      let riskLevel = "Clean"

      if (rateValue > 20) {
        riskLevel = "High Risk"
      } else if (rateValue > 5) {
        riskLevel = "Medium Risk"
      } else if (rateValue > 0) {
        riskLevel = "Low Risk"
      }

      // Add to history
      const historyItem: ScanHistoryItem = {
        name: result.file_info.name,
        result: riskLevel,
        full_result: result,
      }

      setScanHistory((prev) => {
        const newHistory = [historyItem, ...prev]
        // Limit history size to 10 items
        return newHistory.slice(0, 10)
      })

      setCurrentResult(result)
      setScanCompleted(true)
    } catch (error) {
      console.error("Error scanning file:", error)
      setStatusMessage(`Error: ${error instanceof Error ? error.message : "Failed to scan file"}`)
    } finally {
      setScanning(false)
    }
  }

  const clearHistory = () => {
    setScanHistory([])
    setCurrentResult(null)
    setScanCompleted(false)
    localStorage.removeItem("vtScanHistory")
  }

  const loadHistoryItem = (item: ScanHistoryItem) => {
    setCurrentResult(item.full_result)
    setScanCompleted(true)
  }

  const downloadReport = () => {
    if (!currentResult) return

    const jsonString = JSON.stringify(currentResult, null, 2)
    const blob = new Blob([jsonString], { type: "application/json" })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = `vt_report_${currentResult.file_info.name}.json`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  const formatTimestamp = (timestamp: number): string => {
    if (!timestamp) return "N/A"
    return new Date(timestamp * 1000).toLocaleString()
  }

  const renderFileInfo = () => {
    if (!currentResult) return null

    const { file_info } = currentResult

    return (
      <Card className="shadow-md">
        <CardHeader>
          <CardTitle>File Information</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid md:grid-cols-2 gap-4">
            <div>
              <p className="text-sm font-medium">Name</p>
              <p className="text-lg">{file_info.name}</p>

              <p className="text-sm font-medium mt-4">Size</p>
              <p className="text-lg">{file_info.size.toLocaleString()} bytes</p>

              <p className="text-sm font-medium mt-4">Type</p>
              <p className="text-lg">{file_info.type}</p>
            </div>

            <div>
              <p className="text-sm font-medium">First Seen</p>
              <p className="text-lg">{formatTimestamp(file_info.first_seen)}</p>

              <p className="text-sm font-medium mt-4">Last Analyzed</p>
              <p className="text-lg">{formatTimestamp(file_info.last_seen)}</p>
            </div>
          </div>

          <Accordion type="single" collapsible className="mt-4">
            <AccordionItem value="hashes">
              <AccordionTrigger>Hash Information</AccordionTrigger>
              <AccordionContent>
                <div className="space-y-2">
                  <div>
                    <p className="text-sm font-medium">SHA256</p>
                    <p className="text-sm font-mono bg-muted p-2 rounded-md overflow-x-auto">{file_info.sha256}</p>
                  </div>
                  <div>
                    <p className="text-sm font-medium">MD5</p>
                    <p className="text-sm font-mono bg-muted p-2 rounded-md overflow-x-auto">{file_info.md5}</p>
                  </div>
                </div>
              </AccordionContent>
            </AccordionItem>
          </Accordion>
        </CardContent>
      </Card>
    )
  }

  const renderScanSummary = () => {
    if (!currentResult) return null

    const { scan_results } = currentResult
    const total_engines = scan_results.total_engines
    const malicious = scan_results.malicious
    const suspicious = scan_results.suspicious
    const clean = total_engines - malicious - suspicious

    const detection_rate_raw = Number.parseFloat(scan_results.detection_rate.replace("%", "")) || 0

    // Data for pie chart
    const pieData = [
      { name: "Clean", value: clean, color: "#10b981" },
      { name: "Malicious", value: malicious, color: "#ef4444" },
      { name: "Suspicious", value: suspicious, color: "#f59e0b" },
    ]

    let riskLevel = "Clean"
    let riskColor = "text-green-600"
    let riskBgColor = "bg-green-100"
    let riskBorderColor = "border-green-200"
    let riskIcon = <Shield className="h-5 w-5" />

    if (detection_rate_raw > 20) {
      riskLevel = "High Risk"
      riskColor = "text-red-600"
      riskBgColor = "bg-red-100"
      riskBorderColor = "border-red-200"
      riskIcon = <AlertTriangle className="h-5 w-5" />
    } else if (detection_rate_raw > 5) {
      riskLevel = "Medium Risk"
      riskColor = "text-yellow-600"
      riskBgColor = "bg-yellow-100"
      riskBorderColor = "border-yellow-200"
      riskIcon = <AlertTriangle className="h-5 w-5" />
    } else if (detection_rate_raw > 0) {
      riskLevel = "Low Risk"
      riskColor = "text-blue-600"
      riskBgColor = "bg-blue-100"
      riskBorderColor = "border-blue-200"
      riskIcon = <AlertTriangle className="h-5 w-5" />
    }

    return (
      <Card className="shadow-md">
        <CardHeader>
          <CardTitle>Scan Summary</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid md:grid-cols-2 gap-6">
            <div className="flex flex-col">
              <div className={`p-4 rounded-lg ${riskBgColor} ${riskBorderColor} border mb-4`}>
                <div className="flex items-center gap-2 mb-2">
                  {riskIcon}
                  <h3 className={`font-bold ${riskColor}`}>{riskLevel}</h3>
                </div>
                <p className="text-lg font-semibold">Detection Rate: {scan_results.detection_rate}</p>
                <p className="mt-2">
                  {malicious} malicious, {suspicious} suspicious out of {total_engines} engines
                </p>
              </div>

              {detection_rate_raw > 20 && (
                <Alert variant="destructive" className="mb-4">
                  <AlertTriangle className="h-4 w-4" />
                  <AlertTitle>High Risk</AlertTitle>
                  <AlertDescription>This file is likely malicious. Do not execute or open it.</AlertDescription>
                </Alert>
              )}

              {detection_rate_raw > 5 && detection_rate_raw <= 20 && (
                <Alert variant="warning" className="mb-4">
                  <AlertTriangle className="h-4 w-4" />
                  <AlertTitle>Medium Risk</AlertTitle>
                  <AlertDescription>This file is suspicious. Handle with caution.</AlertDescription>
                </Alert>
              )}

              {detection_rate_raw > 0 && detection_rate_raw <= 5 && (
                <Alert variant="info" className="mb-4">
                  <AlertTriangle className="h-4 w-4" />
                  <AlertTitle>Low Risk</AlertTitle>
                  <AlertDescription>This file has minimal detections but still requires caution.</AlertDescription>
                </Alert>
              )}

              {detection_rate_raw === 0 && (
                <Alert variant="success" className="mb-4">
                  <Shield className="h-4 w-4" />
                  <AlertTitle>Clean</AlertTitle>
                  <AlertDescription>No threats detected by any engine. File appears to be safe.</AlertDescription>
                </Alert>
              )}
            </div>

            <div className="h-[300px] flex items-center justify-center">
              <PieChart data={pieData} title="Antivirus Engine Results" donut={true} />
            </div>
          </div>
        </CardContent>
      </Card>
    )
  }

  const renderDetections = () => {
    if (!currentResult) return null

    const { scan_results } = currentResult
    const detections = scan_results.detections

    if (detections.length === 0) {
      return (
        <Card className="shadow-md">
          <CardHeader>
            <CardTitle>Malware Detections</CardTitle>
          </CardHeader>
          <CardContent>
            <Alert variant="success">
              <Shield className="h-4 w-4" />
              <AlertTitle>No Threats Detected</AlertTitle>
              <AlertDescription>No threats were detected by any antivirus engine.</AlertDescription>
            </Alert>
          </CardContent>
        </Card>
      )
    }

    return (
      <Card className="shadow-md">
        <CardHeader>
          <CardTitle>Malware Detections</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Antivirus Engine</TableHead>
                <TableHead>Threat Category</TableHead>
                <TableHead>Detection Name</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {detections.map((detection, index) => (
                <TableRow key={index}>
                  <TableCell className="font-medium">{detection.engine}</TableCell>
                  <TableCell>
                    <span
                      className={`px-2 py-1 rounded-full text-xs font-medium ${
                        detection.category === "malicious" ? "bg-red-100 text-red-800" : "bg-yellow-100 text-yellow-800"
                      }`}
                    >
                      {detection.category}
                    </span>
                  </TableCell>
                  <TableCell>{detection.result}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    )
  }

  const renderAllResults = () => {
    if (!currentResult) return null

    const { detailed_results } = currentResult

    // Convert detailed results to array
    const resultsArray = Object.entries(detailed_results).map(([engine, details]) => ({
      engine,
      category: details.category,
      result: details.result,
      engine_version: details.engine_version,
    }))

    // Get unique categories
    const categories = ["All", ...new Set(resultsArray.map((item) => item.category))].sort()

    // Filter by selected category
    const filteredResults =
      selectedCategory === "All" ? resultsArray : resultsArray.filter((item) => item.category === selectedCategory)

    // Prepare data for bar chart
    const categoryData = categories
      .filter((cat) => cat !== "All")
      .map((category) => ({
        name: category,
        value: resultsArray.filter((item) => item.category === category).length,
        color:
          category === "malicious"
            ? "#ef4444"
            : category === "suspicious"
              ? "#f59e0b"
              : category === "undetected"
                ? "#10b981"
                : "#6b7280",
      }))

    return (
      <Card className="shadow-md">
        <CardHeader>
          <CardTitle>Complete Scan Results</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="mb-4">
            <label htmlFor="category-filter" className="block text-sm font-medium mb-1">
              Filter by Category:
            </label>
            <Select value={selectedCategory} onValueChange={setSelectedCategory}>
              <SelectTrigger id="category-filter" className="w-[200px]">
                <SelectValue placeholder="Select category" />
              </SelectTrigger>
              <SelectContent>
                {categories.map((category) => (
                  <SelectItem key={category} value={category}>
                    {category}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="mb-6">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Antivirus Engine</TableHead>
                  <TableHead>Category</TableHead>
                  <TableHead>Result</TableHead>
                  <TableHead>Engine Version</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredResults.map((item, index) => (
                  <TableRow key={index}>
                    <TableCell className="font-medium">{item.engine}</TableCell>
                    <TableCell>
                      <span
                        className={`px-2 py-1 rounded-full text-xs font-medium ${
                          item.category === "malicious"
                            ? "bg-red-100 text-red-800"
                            : item.category === "suspicious"
                              ? "bg-yellow-100 text-yellow-800"
                              : item.category === "undetected"
                                ? "bg-green-100 text-green-800"
                                : "bg-gray-100 text-gray-800"
                        }`}
                      >
                        {item.category}
                      </span>
                    </TableCell>
                    <TableCell>{item.result || "N/A"}</TableCell>
                    <TableCell>{item.engine_version || "N/A"}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>

          <div className="h-[400px]">
            <BarChart
              data={categoryData}
              title="Results by Category"
              xAxisLabel="Category"
              yAxisLabel="Number of Engines"
            />
          </div>
        </CardContent>
      </Card>
    )
  }

  const renderDynamicAnalysis = () => {
    if (
      !currentResult ||
      !currentResult.dynamic_analysis ||
      !currentResult.dynamic_analysis.behaviors ||
      currentResult.dynamic_analysis.behaviors.length === 0
    ) {
      return (
        <Card className="shadow-md">
          <CardHeader>
            <CardTitle>Dynamic Analysis</CardTitle>
          </CardHeader>
          <CardContent>
            <Alert>
              <AlertTitle>No Dynamic Analysis Data</AlertTitle>
              <AlertDescription>No dynamic analysis data is available for this file.</AlertDescription>
            </Alert>
          </CardContent>
        </Card>
      )
    }

    const behaviors = currentResult.dynamic_analysis.behaviors

    return (
      <Card className="shadow-md">
        <CardHeader>
          <CardTitle>Dynamic Analysis</CardTitle>
          <CardDescription>
            Behavioral analysis from {behaviors.length} sandbox{behaviors.length > 1 ? "es" : ""}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs value={activeBehaviorTab} onValueChange={setActiveBehaviorTab}>
            <TabsList className="grid grid-cols-5 mb-4">
              <TabsTrigger value="processes">
                <Activity className="h-4 w-4 mr-2" />
                Processes
              </TabsTrigger>
              <TabsTrigger value="files">
                <FileText className="h-4 w-4 mr-2" />
                Files
              </TabsTrigger>
              <TabsTrigger value="registry">
                <Registry className="h-4 w-4 mr-2" />
                Registry
              </TabsTrigger>
              <TabsTrigger value="network">
                <Network className="h-4 w-4 mr-2" />
                Network
              </TabsTrigger>
              <TabsTrigger value="mitre">
                <Database className="h-4 w-4 mr-2" />
                MITRE ATT&CK
              </TabsTrigger>
            </TabsList>

            <TabsContent value="processes">
              <div className="space-y-4">
                {behaviors.map((behavior, index) => (
                  <Accordion key={index} type="single" collapsible className="border rounded-md">
                    <AccordionItem value="processes">
                      <AccordionTrigger className="px-4">
                        <div className="flex items-center gap-2">
                          <Activity className="h-4 w-4" />
                          <span>Processes in {behavior.sandbox_name}</span>
                        </div>
                      </AccordionTrigger>
                      <AccordionContent className="px-4 pb-4">
                        {behavior.processes_created && behavior.processes_created.length > 0 ? (
                          <ScrollArea className="h-[300px] rounded-md border p-4">
                            <div className="space-y-2">
                              {behavior.processes_created.map((process, idx) => (
                                <div key={idx} className="p-2 bg-muted rounded-md">
                                  <code className="text-xs break-all">{process}</code>
                                </div>
                              ))}
                            </div>
                          </ScrollArea>
                        ) : (
                          <p className="text-muted-foreground">No process information available</p>
                        )}
                      </AccordionContent>
                    </AccordionItem>
                  </Accordion>
                ))}
              </div>
            </TabsContent>

            <TabsContent value="files">
              <div className="space-y-4">
                {behaviors.map((behavior, index) => (
                  <Accordion key={index} type="single" collapsible className="border rounded-md">
                    <AccordionItem value="files">
                      <AccordionTrigger className="px-4">
                        <div className="flex items-center gap-2">
                          <FileText className="h-4 w-4" />
                          <span>Files in {behavior.sandbox_name}</span>
                        </div>
                      </AccordionTrigger>
                      <AccordionContent className="px-4 pb-4">
                        {behavior.files_dropped && behavior.files_dropped.length > 0 ? (
                          <ScrollArea className="h-[300px] rounded-md border p-4">
                            <Table>
                              <TableHeader>
                                <TableRow>
                                  <TableHead>Path</TableHead>
                                  <TableHead>Type</TableHead>
                                  <TableHead>SHA256</TableHead>
                                </TableRow>
                              </TableHeader>
                              <TableBody>
                                {behavior.files_dropped.map((file, idx) => (
                                  <TableRow key={idx}>
                                    <TableCell className="font-mono text-xs break-all">{file.path}</TableCell>
                                    <TableCell>{file.type || "Unknown"}</TableCell>
                                    <TableCell className="font-mono text-xs break-all">{file.sha256}</TableCell>
                                  </TableRow>
                                ))}
                              </TableBody>
                            </Table>
                          </ScrollArea>
                        ) : (
                          <p className="text-muted-foreground">No file information available</p>
                        )}
                      </AccordionContent>
                    </AccordionItem>
                  </Accordion>
                ))}
              </div>
            </TabsContent>

            <TabsContent value="registry">
              <div className="space-y-4">
                {behaviors.map((behavior, index) => (
                  <Accordion key={index} type="single" collapsible className="border rounded-md">
                    <AccordionItem value="registry">
                      <AccordionTrigger className="px-4">
                        <div className="flex items-center gap-2">
                          <Registry className="h-4 w-4" />
                          <span>Registry in {behavior.sandbox_name}</span>
                        </div>
                      </AccordionTrigger>
                      <AccordionContent className="px-4 pb-4">
                        {behavior.registry_keys_opened && behavior.registry_keys_opened.length > 0 ? (
                          <ScrollArea className="h-[300px] rounded-md border p-4">
                            <div className="space-y-2">
                              {behavior.registry_keys_opened.map((key, idx) => (
                                <div key={idx} className="p-2 bg-muted rounded-md">
                                  <code className="text-xs break-all">{key}</code>
                                </div>
                              ))}
                            </div>
                          </ScrollArea>
                        ) : (
                          <p className="text-muted-foreground">No registry information available</p>
                        )}
                      </AccordionContent>
                    </AccordionItem>
                  </Accordion>
                ))}
              </div>
            </TabsContent>

            <TabsContent value="network">
              <div className="space-y-4">
                {behaviors.map((behavior, index) => (
                  <Accordion key={index} type="single" collapsible className="border rounded-md">
                    <AccordionItem value="network">
                      <AccordionTrigger className="px-4">
                        <div className="flex items-center gap-2">
                          <Network className="h-4 w-4" />
                          <span>Network in {behavior.sandbox_name}</span>
                        </div>
                      </AccordionTrigger>
                      <AccordionContent className="px-4 pb-4">
                        {behavior.network_connections && behavior.network_connections.length > 0 ? (
                          <Table>
                            <TableHeader>
                              <TableRow>
                                <TableHead>Destination IP</TableHead>
                                <TableHead>Port</TableHead>
                                <TableHead>Protocol</TableHead>
                              </TableRow>
                            </TableHeader>
                            <TableBody>
                              {behavior.network_connections.map((conn, idx) => (
                                <TableRow key={idx}>
                                  <TableCell>{conn.destination_ip}</TableCell>
                                  <TableCell>{conn.destination_port}</TableCell>
                                  <TableCell>{conn.transport_layer_protocol}</TableCell>
                                </TableRow>
                              ))}
                            </TableBody>
                          </Table>
                        ) : (
                          <p className="text-muted-foreground">No network information available</p>
                        )}
                      </AccordionContent>
                    </AccordionItem>
                  </Accordion>
                ))}
              </div>
            </TabsContent>

            <TabsContent value="mitre">
              <div className="space-y-4">
                {behaviors.map((behavior, index) => (
                  <Accordion key={index} type="single" collapsible className="border rounded-md">
                    <AccordionItem value="mitre">
                      <AccordionTrigger className="px-4">
                        <div className="flex items-center gap-2">
                          <Database className="h-4 w-4" />
                          <span>MITRE ATT&CK in {behavior.sandbox_name}</span>
                        </div>
                      </AccordionTrigger>
                      <AccordionContent className="px-4 pb-4">
                        {behavior.mitre_techniques && behavior.mitre_techniques.length > 0 ? (
                          <Table>
                            <TableHeader>
                              <TableRow>
                                <TableHead>Technique ID</TableHead>
                                <TableHead>Description</TableHead>
                                <TableHead>Severity</TableHead>
                              </TableRow>
                            </TableHeader>
                            <TableBody>
                              {behavior.mitre_techniques.map((technique, idx) => (
                                <TableRow key={idx}>
                                  <TableCell>
                                    <a
                                      href={`https://attack.mitre.org/techniques/${technique.id}`}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      className="flex items-center gap-1 text-primary hover:underline"
                                    >
                                      {technique.id}
                                      <ExternalLink className="h-3 w-3" />
                                    </a>
                                  </TableCell>
                                  <TableCell>{technique.signature_description || "No description available"}</TableCell>
                                  <TableCell>{technique.severity || "Unknown"}</TableCell>
                                </TableRow>
                              ))}
                            </TableBody>
                          </Table>
                        ) : (
                          <p className="text-muted-foreground">No MITRE ATT&CK information available</p>
                        )}
                      </AccordionContent>
                    </AccordionItem>
                  </Accordion>
                ))}
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    )
  }

  const renderReport = () => {
    if (!currentResult || !currentResult.report) return null

    return (
      <Card className="shadow-md">
        <CardHeader>
          <CardTitle>Analysis Report</CardTitle>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-[500px] rounded-md border p-4">
            <pre className="whitespace-pre-wrap text-sm">{currentResult.report}</pre>
          </ScrollArea>
        </CardContent>
        <CardFooter>
          <Button onClick={downloadReport} className="ml-auto">
            <Download className="h-4 w-4 mr-2" />
            Download Full Report
          </Button>
        </CardFooter>
      </Card>
    )
  }

  return (
    <div className="container py-8">
      <div className="flex flex-col gap-6">
        <div className="flex items-center gap-3 mb-2">
          <Link href="/" className="flex items-center gap-2 text-muted-foreground hover:text-foreground">
            <ArrowLeft className="h-4 w-4" />
            <span className="text-sm font-medium">Back to Home</span>
          </Link>
        </div>

        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold tracking-tight mb-2">Dynamic Malware Analysis</h1>
            <p className="text-muted-foreground">
              Upload files to analyze their behavior in a secure sandbox environment
            </p>
          </div>
        </div>

        <div className="grid md:grid-cols-3 gap-6">
          <div className="md:col-span-2">
            <Card className="shadow-md">
              <CardHeader>
                <CardTitle>File Scanner</CardTitle>
                <CardDescription>Upload a file to analyze its behavior in a secure sandbox environment</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">

                  <div className="border-2 border-dashed rounded-lg p-6 flex flex-col items-center justify-center">
                    <input ref={fileInputRef} type="file" onChange={handleFileChange} className="hidden" />
                    <FileText className="h-10 w-10 text-muted-foreground mb-4" />
                    <h3 className="font-medium mb-2">Upload File for Analysis</h3>
                    <p className="text-sm text-muted-foreground text-center mb-4">
                      Drag and drop your file here, or click to browse
                    </p>
                    <Button onClick={() => fileInputRef.current?.click()}>
                      <Upload className="h-4 w-4 mr-2" />
                      Select File
                    </Button>
                    {file && (
                      <div className="mt-4 text-sm">
                        Selected file: <span className="font-medium">{file.name}</span> ({(file.size / 1024).toFixed(2)}{" "}
                        KB)
                      </div>
                    )}
                  </div>

                  {file && !scanning && !scanCompleted && (
                    <Button className="w-full" onClick={handleScan}>
                      <Shield className="h-4 w-4 mr-2" />
                      Analyze File
                    </Button>
                  )}

                  {scanning && (
                    <div className="space-y-2">
                      <Progress value={progress} className="w-full" />
                      <p className="text-sm text-center">{statusMessage}</p>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>

            {scanCompleted && currentResult && (
              <div className="mt-6 space-y-6">
                <Tabs defaultValue="overview" value={activeTab} onValueChange={setActiveTab}>
                  <TabsList className="grid w-full grid-cols-5">
                    <TabsTrigger value="overview">Overview</TabsTrigger>
                    <TabsTrigger value="detections">Detections</TabsTrigger>
                    <TabsTrigger value="all-results">All Results</TabsTrigger>
                    <TabsTrigger value="dynamic">Dynamic Analysis</TabsTrigger>
                    <TabsTrigger value="report">Report</TabsTrigger>
                  </TabsList>

                  <div className="mt-4">{renderFileInfo()}</div>

                  <TabsContent value="overview" className="mt-4">
                    {renderScanSummary()}
                  </TabsContent>

                  <TabsContent value="detections" className="mt-4">
                    {renderDetections()}
                  </TabsContent>

                  <TabsContent value="all-results" className="mt-4">
                    {renderAllResults()}
                  </TabsContent>

                  <TabsContent value="dynamic" className="mt-4">
                    {renderDynamicAnalysis()}
                  </TabsContent>

                  <TabsContent value="report" className="mt-4">
                    {renderReport()}
                  </TabsContent>
                </Tabs>
              </div>
            )}
          </div>

          <div className="space-y-6">
            <Card className="shadow-md">
              <CardHeader>
                <CardTitle>Scan History</CardTitle>
              </CardHeader>
              <CardContent>
                {scanHistory.length > 0 ? (
                  <div className="space-y-2">
                    {scanHistory.map((item, index) => (
                      <Button
                        key={index}
                        variant="outline"
                        className="w-full justify-start text-left h-auto py-2 px-3"
                        onClick={() => loadHistoryItem(item)}
                      >
                        <div className="flex items-center gap-2 w-full">
                          <div
                            className={`w-2 h-2 rounded-full ${
                              item.result.includes("High")
                                ? "bg-red-500"
                                : item.result.includes("Medium")
                                  ? "bg-yellow-500"
                                  : item.result.includes("Low")
                                    ? "bg-blue-500"
                                    : "bg-green-500"
                            }`}
                          />
                          <div className="truncate flex-1">{item.name}</div>
                          <div className="text-xs text-muted-foreground">{item.result}</div>
                        </div>
                      </Button>
                    ))}

                    <Button variant="outline" className="w-full mt-4" onClick={clearHistory}>
                      <Trash2 className="h-4 w-4 mr-2" />
                      Clear History
                    </Button>
                  </div>
                ) : (
                  <div className="text-center py-6">
                    <p className="text-muted-foreground">No scan history yet</p>
                  </div>
                )}
              </CardContent>
            </Card>

            <Card className="shadow-md">
              <CardHeader>
                <CardTitle>About Dynamic Analysis</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground">
                  Dynamic analysis executes files in a secure sandbox environment to observe their behavior. This helps
                  identify:
                </p>
                <div className="mt-4 space-y-2">
                  <div className="flex items-center gap-2">
                    <Activity className="h-4 w-4 text-primary" />
                    <span className="text-sm">Process creation and execution flow</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <FileText className="h-4 w-4 text-primary" />
                    <span className="text-sm">File system interactions</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Registry className="h-4 w-4 text-primary" />
                    <span className="text-sm">Registry modifications</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Network className="h-4 w-4 text-primary" />
                    <span className="text-sm">Network communications</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Database className="h-4 w-4 text-primary" />
                    <span className="text-sm">MITRE ATT&CK techniques</span>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </div>
  )
}
