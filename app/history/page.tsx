"use client"

import { useState, useEffect } from "react"
import Link from "next/link"
import {
  FileWarning,
  FileSpreadsheet,
  FileIcon,
  FileCode,
  Shield,
  AlertTriangle,
  Search,
  Smartphone,
  Trash2,
} from "lucide-react"
import { Card, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { FileType } from "@/lib/types"
import { fetchScanHistory, clearScanHistory } from "@/lib/api"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog"

export default function HistoryPage() {
  const [history, setHistory] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [searchTerm, setSearchTerm] = useState("")
  const [activeTab, setActiveTab] = useState("all")

  useEffect(() => {
    const loadHistory = async () => {
      try {
        const data = await fetchScanHistory()
        setHistory(data)
      } catch (error) {
        console.error("Failed to load history:", error)
      } finally {
        setLoading(false)
      }
    }

    loadHistory()
  }, [])

  const getFileIcon = (fileType: FileType) => {
    switch (fileType) {
      case FileType.PE:
        return <FileWarning className="h-5 w-5" />
      case FileType.OFFICE:
        return <FileSpreadsheet className="h-5 w-5" />
      case FileType.PDF:
        return <FileIcon className="h-5 w-5" />
      case FileType.SCRIPT:
        return <FileCode className="h-5 w-5" />
      case FileType.APK:
        return <Smartphone className="h-5 w-5" />
      default:
        return <FileIcon className="h-5 w-5" />
    }
  }

  const getResultBadge = (result: string) => {
    switch (result) {
      case "clean":
      case "legitimate":
        return (
          <Badge variant="outline" className="bg-green-50 text-green-700 border-green-200 flex gap-1 items-center">
            <Shield className="h-3.5 w-3.5" />
            <span>Clean</span>
          </Badge>
        )
      case "malicious":
        return (
          <Badge variant="outline" className="bg-red-50 text-red-700 border-red-200 flex gap-1 items-center">
            <AlertTriangle className="h-3.5 w-3.5" />
            <span>Malicious</span>
          </Badge>
        )
      case "suspicious":
        return (
          <Badge variant="outline" className="bg-yellow-50 text-yellow-700 border-yellow-200 flex gap-1 items-center">
            <AlertTriangle className="h-3.5 w-3.5" />
            <span>Suspicious</span>
          </Badge>
        )
      default:
        return <Badge>Unknown</Badge>
    }
  }

  const handleClearHistory = async () => {
    await clearScanHistory()
    setHistory([])
  }

  const filteredHistory = history.filter((item) => {
    const matchesSearch = item.fileName.toLowerCase().includes(searchTerm.toLowerCase())
    const matchesTab = activeTab === "all" || item.fileType === activeTab
    return matchesSearch && matchesTab
  })

  const formatDate = (dateString: string) => {
    const date = new Date(dateString)
    return new Intl.DateTimeFormat("en-US", {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    }).format(date)
  }

  const getAnalysisLink = (item: any) => {
    switch (item.fileType) {
      case FileType.PE:
        return `/analysis/pe?id=${item.id}`
      case FileType.PDF:
        return `/analysis/pdf?id=${item.id}`
      case FileType.OFFICE:
        return `/analysis/office?id=${item.id}`
      case FileType.SCRIPT:
        return `/analysis/script?id=${item.id}`
      case FileType.APK:
        return `/analysis/apk?id=${item.id}`
      default:
        return `/analysis/general?id=${item.id}&type=${item.fileType}`
    }
  }

  return (
    <div className="container py-8">
      <div className="flex flex-col gap-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold tracking-tight mb-2">Scan History</h1>
            <p className="text-muted-foreground">View and manage your previous file scans</p>
          </div>
          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button variant="destructive" className="gap-2">
                <Trash2 className="h-4 w-4" />
                Clear History
              </Button>
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>Are you sure?</AlertDialogTitle>
                <AlertDialogDescription>
                  This action will permanently delete all scan history. This action cannot be undone.
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>Cancel</AlertDialogCancel>
                <AlertDialogAction onClick={handleClearHistory}>Delete</AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        </div>

        <div className="flex flex-col sm:flex-row gap-4 items-start sm:items-center justify-between">
          <div className="relative w-full sm:w-auto max-w-sm">
            <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input
              type="search"
              placeholder="Search by filename..."
              className="pl-9 w-full"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>
          <Button variant="outline" onClick={() => setSearchTerm("")}>
            Clear Filters
          </Button>
        </div>

        <Tabs defaultValue="all" value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="grid grid-cols-6 w-full max-w-md">
            <TabsTrigger value="all">All</TabsTrigger>
            <TabsTrigger value={FileType.PE}>PE</TabsTrigger>
            <TabsTrigger value={FileType.OFFICE}>Office</TabsTrigger>
            <TabsTrigger value={FileType.PDF}>PDF</TabsTrigger>
            <TabsTrigger value={FileType.SCRIPT}>Script</TabsTrigger>
            <TabsTrigger value={FileType.APK}>APK</TabsTrigger>
          </TabsList>
        </Tabs>

        {loading ? (
          <div className="flex justify-center py-12">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
          </div>
        ) : filteredHistory.length === 0 ? (
          <Card className="shadow-md">
            <CardContent className="flex flex-col items-center justify-center py-12">
              <div className="rounded-full bg-muted p-3 mb-4">
                <Search className="h-6 w-6 text-muted-foreground" />
              </div>
              <h3 className="text-lg font-medium mb-2">No scan history found</h3>
              <p className="text-muted-foreground text-center max-w-md mb-6">
                {searchTerm
                  ? "No results match your search criteria. Try a different search term."
                  : "You haven't scanned any files yet. Upload a file to get started."}
              </p>
              <Button asChild>
                <Link href="/">Scan a File</Link>
              </Button>
            </CardContent>
          </Card>
        ) : (
          <div className="grid gap-4">
            {filteredHistory.map((item) => (
              <Card key={item.id} className="overflow-hidden shadow-sm hover:shadow-md transition-all">
                <Link href={getAnalysisLink(item)}>
                  <div className="flex flex-col sm:flex-row sm:items-center gap-4 p-4 hover:bg-slate-50 dark:hover:bg-slate-900/50 transition-colors">
                    <div className="flex-shrink-0 flex items-center justify-center w-10 h-10 rounded-full bg-primary/10">
                      {getFileIcon(item.fileType)}
                    </div>

                    <div className="flex-grow min-w-0">
                      <div className="flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-4">
                        <h3 className="font-medium truncate">{item.fileName}</h3>
                        <div className="flex items-center gap-2">
                          {getResultBadge(item.result)}
                          <Badge variant="outline" className="bg-slate-100 border-slate-200 flex gap-1 items-center">
                            {item.fileType.toUpperCase()}
                          </Badge>
                        </div>
                      </div>
                      <div className="flex items-center gap-4 text-sm text-muted-foreground mt-1">
                        <span>Scanned: {formatDate(item.scanDate)}</span>
                        <span>Risk Score: {item.riskScore}%</span>
                        <span>Threats: {item.threatCount}</span>
                      </div>
                    </div>

                    <div className="flex-shrink-0 self-end sm:self-center">
                      <Button variant="ghost" size="sm">
                        View Details
                      </Button>
                    </div>
                  </div>
                </Link>
              </Card>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
