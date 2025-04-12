"use client"

import type React from "react"

import { useState } from "react"
import { useRouter } from "next/navigation"
import {
  FileUp,
  FileIcon as FileDll,
  FileSpreadsheet,
  FileIcon as FilePdf,
  FileCode,
  Upload,
  Smartphone,
} from "lucide-react"
import { FileType } from "@/lib/types"
import { uploadFileForAnalysis } from "@/lib/api"
import { Progress } from "@/components/ui/progress"

interface FileUploadBoxProps {
  type: FileType
  title: string
  description: string
  active: boolean
}

export default function FileUploadBox({ type, title, description, active }: FileUploadBoxProps) {
  const router = useRouter()
  const [isDragging, setIsDragging] = useState(false)
  const [file, setFile] = useState<File | null>(null)
  const [isUploading, setIsUploading] = useState(false)
  const [uploadProgress, setUploadProgress] = useState(0)
  const [error, setError] = useState<string | null>(null)

  const handleDragOver = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    if (active) {
      setIsDragging(true)
    }
  }

  const handleDragLeave = () => {
    setIsDragging(false)
  }

  const handleDrop = async (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    setIsDragging(false)

    if (e.dataTransfer.files && e.dataTransfer.files.length > 0 && active) {
      const droppedFile = e.dataTransfer.files[0]
      setFile(droppedFile)
      await processFile(droppedFile)
    }
  }

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0 && active) {
      const selectedFile = e.target.files[0]
      setFile(selectedFile)
      await processFile(selectedFile)
    }
  }

  const processFile = async (fileToProcess: File) => {
    setIsUploading(true)
    setError(null)
    setUploadProgress(0)

    // Simulate upload progress
    const progressInterval = setInterval(() => {
      setUploadProgress((prev) => {
        const newProgress = prev + 10
        if (newProgress >= 90) {
          clearInterval(progressInterval)
          return 90
        }
        return newProgress
      })
    }, 300)

    try {
      // Upload the file for analysis
      const result = await uploadFileForAnalysis(fileToProcess, type)

      // Complete the progress bar
      clearInterval(progressInterval)
      setUploadProgress(100)

      // Navigate to the appropriate analysis page with the result data
      setTimeout(() => {
        if (type === FileType.PE) {
          router.push(`/analysis/pe?data=${encodeURIComponent(JSON.stringify(result))}`)
        } else if (type === FileType.PDF) {
          router.push(`/analysis/pdf?data=${encodeURIComponent(JSON.stringify(result))}`)
        } else if (type === FileType.OFFICE) {
          router.push(`/analysis/office?data=${encodeURIComponent(JSON.stringify(result))}`)
        } else if (type === FileType.SCRIPT) {
          router.push(`/analysis/script?data=${encodeURIComponent(JSON.stringify(result))}`)
        } else if (type === FileType.APK) {
          router.push(`/analysis/apk?data=${encodeURIComponent(JSON.stringify(result))}`)
        }
      }, 500)
    } catch (error) {
      console.error("Error uploading file:", error)
      clearInterval(progressInterval)
      setUploadProgress(0)
      setError("Failed to upload file. Please try again.")
      setIsUploading(false)
    }
  }

  const getIcon = () => {
    switch (type) {
      case FileType.PE:
        return <FileDll className="h-12 w-12 text-primary" />
      case FileType.OFFICE:
        return <FileSpreadsheet className="h-12 w-12 text-primary" />
      case FileType.PDF:
        return <FilePdf className="h-12 w-12 text-primary" />
      case FileType.SCRIPT:
        return <FileCode className="h-12 w-12 text-primary" />
      case FileType.APK:
        return <Smartphone className="h-12 w-12 text-primary" />
      default:
        return <FileUp className="h-12 w-12 text-primary" />
    }
  }

  return (
    <div
      className={`
        ${isDragging ? "border-primary border-2 bg-primary/5" : "border border-slate-200 dark:border-slate-800"} 
        ${active ? "cursor-pointer hover:border-primary/50 hover:shadow-md transition-all" : "opacity-50 cursor-not-allowed"}
        ${isUploading ? "bg-muted/30" : ""}
        rounded-xl bg-white dark:bg-slate-900 shadow-sm
      `}
    >
      <div
        className="flex flex-col items-center justify-center p-6 h-56"
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
      >
        <input
          type="file"
          id={`file-upload-${type}`}
          className="hidden"
          onChange={handleFileChange}
          disabled={!active || isUploading}
        />
        <label
          htmlFor={`file-upload-${type}`}
          className="flex flex-col items-center justify-center space-y-4 h-full w-full cursor-pointer"
        >
          {isUploading ? (
            <div className="flex flex-col items-center justify-center w-full space-y-4">
              <div className="rounded-full bg-primary/10 p-3">
                <Upload className="h-8 w-8 text-primary animate-pulse" />
              </div>
              <div className="text-center">
                <h3 className="font-medium mb-1">Uploading...</h3>
                <p className="text-sm text-muted-foreground">{file?.name}</p>
              </div>
              <Progress value={uploadProgress} className="w-full h-2" />
            </div>
          ) : (
            <>
              <div className="rounded-full bg-primary/10 p-3">{getIcon()}</div>
              <div className="text-center">
                <h3 className="font-medium mb-1">{title}</h3>
                <p className="text-sm text-muted-foreground">{description}</p>
              </div>
              {error && <p className="text-xs text-destructive">{error}</p>}
              {active ? (
                <div className="text-xs text-muted-foreground mt-2 flex items-center gap-1 bg-slate-100 dark:bg-slate-800 px-3 py-1.5 rounded-full">
                  <Upload className="h-3 w-3" />
                  {file ? file.name : "Drag & drop or click to upload"}
                </div>
              ) : (
                <div className="text-xs text-muted-foreground mt-2">Coming soon</div>
              )}
            </>
          )}
        </label>
      </div>
    </div>
  )
}
