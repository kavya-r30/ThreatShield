"use client"

import type React from "react"

import { useState, useRef, useEffect } from "react"
import Link from "next/link"
import { ArrowLeft, Send, Bot, User, Loader2, ShieldAlert, Paperclip, X, FileText } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Textarea } from "@/components/ui/textarea"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Separator } from "@/components/ui/separator"
import type { ChatMessage, FileType } from "@/lib/types"
import { cn } from "@/lib/utils"
import { analyzeReportWithAI, askAI, uploadFileForAnalysis } from "@/lib/api"

export default function ChatbotPage() {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: "welcome",
      role: "assistant",
      content:
        "Hello! I'm your ThreatShield AI assistant. I can answer questions about malware, cybersecurity threats, and help you understand analysis results. How can I help you today?",
      timestamp: new Date(),
    },
  ])
  const [input, setInput] = useState("")
  const [isLoading, setIsLoading] = useState(false)
  const [attachment, setAttachment] = useState<File | null>(null)
  const [jsonData, setJsonData] = useState<any>(null)
  const [activeTab, setActiveTab] = useState("chat")
  const fileInputRef = useRef<HTMLInputElement>(null)
  const jsonFileInputRef = useRef<HTMLInputElement>(null)
  const messagesEndRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    scrollToBottom()
  }, [messages])

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" })
  }

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      const file = e.target.files[0]
      setAttachment(file)

      if (file.type === "application/json") {
        try {
          const text = await file.text()
          const data = JSON.parse(text)
          setJsonData(data)
        } catch (error) {
          console.error("Error parsing JSON file:", error)
          alert("Invalid JSON file. Please upload a valid JSON file.")
        }
      }
    }
  }

  const handleJsonFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      const file = e.target.files[0]
      try {
        const text = await file.text()
        const data = JSON.parse(text)
        setJsonData(data)
      } catch (error) {
        console.error("Error parsing JSON file:", error)
        alert("Invalid JSON file. Please upload a valid JSON file.")
      }
    }
  }

  const handleAttachmentClick = () => {
    fileInputRef.current?.click()
  }

  const handleJsonAttachmentClick = () => {
    jsonFileInputRef.current?.click()
  }

  const removeAttachment = () => {
    setAttachment(null)
    if (fileInputRef.current) {
      fileInputRef.current.value = ""
    }
  }

  const analyzeJsonReport = async () => {
    if (!jsonData) return

    setIsLoading(true)
    const userMessage: ChatMessage = {
      id: Date.now().toString(),
      role: "user",
      content: "Please analyze this malware analysis report.",
      timestamp: new Date(),
    }

    setMessages((prev) => [...prev, userMessage])

    try {
      const result = await analyzeReportWithAI(jsonData)

      const assistantMessage: ChatMessage = {
        id: (Date.now() + 1).toString(),
        role: "assistant",
        content: result.report || "I've analyzed the report but couldn't generate a detailed analysis.",
        timestamp: new Date(),
      }

      setMessages((prev) => [...prev, assistantMessage])
      setJsonData(null)
      setActiveTab("chat")
    } catch (error) {
      console.error("Error analyzing JSON report:", error)

      const errorMessage: ChatMessage = {
        id: (Date.now() + 1).toString(),
        role: "assistant",
        content: "I'm sorry, I encountered an error analyzing the report. Please try again later.",
        timestamp: new Date(),
      }

      setMessages((prev) => [...prev, errorMessage])
    } finally {
      setIsLoading(false)
    }
  }

  const suggestedQuestions = [
    "What are the most common signs of malware in PE files?",
    "Explain what high entropy in file sections means",
    "How can I protect my system from ransomware?",
    "What does it mean when DllCharacteristics is set to 0?",
    "How do I identify a phishing email?",
    "What are the latest malware trends in 2023?",
  ]

  const handleSuggestedQuestion = (question: string) => {
    setInput(question)
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if ((!input.trim() && !attachment) || isLoading) return

    const userMessage: ChatMessage = {
      id: Date.now().toString(),
      role: "user",
      content: input || (attachment ? `Attached file: ${attachment.name}` : ""),
      timestamp: new Date(),
    }

    setMessages((prev) => [...prev, userMessage])
    setInput("")
    setIsLoading(true)

    try {
      let response: string

      if (attachment) {
        // If it's a JSON file, use analyzeReportWithAI
        if (attachment.type === "application/json") {
          const text = await attachment.text()
          const jsonData = JSON.parse(text)
          const result = await analyzeReportWithAI(jsonData)
          response = result.report
        } else {
          // For other file types, upload for analysis first
          const fileType = determineFileType(attachment.name)
          const analysisResult = await uploadFileForAnalysis(attachment, fileType)

          // Then analyze the result with AI
          const aiAnalysis = await analyzeReportWithAI(analysisResult)
          response = aiAnalysis.report
        }
      } else {
        // For text-only queries
        const result = await askAI(input)
        response = result.response
      }

      const assistantMessage: ChatMessage = {
        id: (Date.now() + 1).toString(),
        role: "assistant",
        content: response,
        timestamp: new Date(),
      }

      setMessages((prev) => [...prev, assistantMessage])
      setAttachment(null)
    } catch (error) {
      console.error("Error getting AI response:", error)

      const errorMessage: ChatMessage = {
        id: (Date.now() + 1).toString(),
        role: "assistant",
        content: "I'm sorry, I encountered an error processing your request. Please try again later.",
        timestamp: new Date(),
      }

      setMessages((prev) => [...prev, errorMessage])
    } finally {
      setIsLoading(false)
    }
  }

  // Helper function to determine file type
  const determineFileType = (filename: string): FileType => {
    const extension = filename.split(".").pop()?.toLowerCase() || ""

    if (["exe", "dll", "sys", "ocx", "scr"].includes(extension)) {
      return FileType.PE
    } else if (["doc", "docx", "xls", "xlsx", "ppt", "pptx"].includes(extension)) {
      return FileType.OFFICE
    } else if (extension === "pdf") {
      return FileType.PDF
    } else if (["bat", "ps1", "vbs", "js", "py", "sh"].includes(extension)) {
      return FileType.SCRIPT
    } else if (extension === "apk") {
      return FileType.APK
    }

    return FileType.PE
  }

  return (
    <div className="flex min-h-screen flex-col bg-slate-50 dark:bg-slate-950/30">
      <header className="sticky top-0 z-10 border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="container flex h-16 items-center">
          <Link href="/" className="flex items-center gap-2">
            <ArrowLeft className="h-4 w-4" />
            <span className="text-sm font-medium">Back to Home</span>
          </Link>
        </div>
      </header>
      <main className="flex-1 container py-8">
        <div className="max-w-5xl mx-auto">
          <div className="flex items-center gap-3 mb-6">
            <div className="rounded-full bg-primary/10 p-2">
              <ShieldAlert className="h-6 w-6 text-primary" />
            </div>
            <div>
              <h1 className="text-3xl font-bold tracking-tight">ThreatShield AI Assistant</h1>
              <p className="text-muted-foreground">Ask questions about malware, threats, and cybersecurity</p>
            </div>
          </div>

          <Tabs value={activeTab} onValueChange={setActiveTab} className="mb-6">
            <TabsList className="grid w-full max-w-md grid-cols-2">
              <TabsTrigger value="chat">Chat Assistant</TabsTrigger>
              <TabsTrigger value="analyze">Analyze Report</TabsTrigger>
            </TabsList>

            <TabsContent value="chat" className="mt-4">
              <div className="grid md:grid-cols-4 gap-6">
                <div className="md:col-span-3">
                  <Card className="mb-4 border-slate-200 dark:border-slate-800 shadow-md">
                    <CardContent className="p-0">
                      <ScrollArea className="h-[500px] p-4">
                        <div className="space-y-4 pb-4">
                          {messages.map((message) => (
                            <div
                              key={message.id}
                              className={cn("flex", message.role === "assistant" ? "justify-start" : "justify-end")}
                            >
                              <div
                                className={cn(
                                  "flex gap-3 max-w-[80%] p-3 rounded-lg",
                                  message.role === "assistant"
                                    ? "bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-sm"
                                    : "bg-primary text-primary-foreground",
                                )}
                              >
                                <div className="flex-shrink-0 mt-1">
                                  {message.role === "assistant" ? (
                                    <Bot className="h-5 w-5 text-primary" />
                                  ) : (
                                    <User className="h-5 w-5" />
                                  )}
                                </div>
                                <div>
                                  <div className="text-sm whitespace-pre-wrap">{message.content}</div>
                                  <div className="text-xs text-muted-foreground mt-1">
                                    {message.timestamp.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                                  </div>
                                </div>
                              </div>
                            </div>
                          ))}
                          {isLoading && (
                            <div className="flex justify-start">
                              <div className="flex gap-3 max-w-[80%] bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-3 rounded-lg shadow-sm">
                                <div className="flex-shrink-0 mt-1">
                                  <Bot className="h-5 w-5 text-primary" />
                                </div>
                                <div className="flex items-center gap-2">
                                  <Loader2 className="h-4 w-4 animate-spin" />
                                  <span className="text-sm">Thinking...</span>
                                </div>
                              </div>
                            </div>
                          )}
                          <div ref={messagesEndRef} />
                        </div>
                      </ScrollArea>
                    </CardContent>
                  </Card>

                  <form onSubmit={handleSubmit} className="flex flex-col gap-2">
                    {attachment && (
                      <div className="flex items-center gap-2 bg-slate-100 dark:bg-slate-800 p-2 rounded-md">
                        <Paperclip className="h-4 w-4 text-muted-foreground" />
                        <span className="text-sm truncate flex-1">{attachment.name}</span>
                        <Button
                          type="button"
                          variant="ghost"
                          size="icon"
                          className="h-6 w-6"
                          onClick={removeAttachment}
                        >
                          <X className="h-4 w-4" />
                        </Button>
                      </div>
                    )}
                    <div className="flex gap-2">
                      <Textarea
                        placeholder="Type your message here..."
                        value={input}
                        onChange={(e) => setInput(e.target.value)}
                        className="min-h-[60px] shadow-sm"
                        onKeyDown={(e) => {
                          if (e.key === "Enter" && !e.shiftKey) {
                            e.preventDefault()
                            handleSubmit(e)
                          }
                        }}
                      />
                      <div className="flex flex-col gap-2">
                        <Button
                          type="button"
                          size="icon"
                          variant="outline"
                          onClick={handleAttachmentClick}
                          className="shadow-sm"
                        >
                          <Paperclip className="h-4 w-4" />
                          <span className="sr-only">Attach file</span>
                        </Button>
                        <Button
                          type="submit"
                          size="icon"
                          disabled={(!input.trim() && !attachment) || isLoading}
                          className="shadow-sm"
                        >
                          <Send className="h-4 w-4" />
                          <span className="sr-only">Send</span>
                        </Button>
                      </div>
                      <input type="file" ref={fileInputRef} onChange={handleFileChange} className="hidden" />
                    </div>
                  </form>
                </div>

                <div className="space-y-4">
                  <Card className="shadow-md">
                    <CardContent className="p-4">
                      <h3 className="font-medium mb-3">Suggested Questions</h3>
                      <div className="space-y-2">
                        {suggestedQuestions.map((question, index) => (
                          <Button
                            key={index}
                            variant="outline"
                            className="w-full justify-start text-left h-auto py-2 px-3 text-sm"
                            onClick={() => handleSuggestedQuestion(question)}
                          >
                            {question}
                          </Button>
                        ))}
                      </div>
                    </CardContent>
                  </Card>

                  <Card className="shadow-md bg-primary/5 border-primary/20">
                    <CardContent className="p-4">
                      <h3 className="font-medium mb-2">Upload Analysis</h3>
                      <p className="text-sm text-muted-foreground mb-3">
                        You can upload analysis results for the AI to explain findings in detail.
                      </p>
                      <Button variant="outline" className="w-full" onClick={handleAttachmentClick}>
                        <Paperclip className="h-4 w-4 mr-2" />
                        Upload File
                      </Button>
                    </CardContent>
                  </Card>
                </div>
              </div>
            </TabsContent>

            <TabsContent value="analyze" className="mt-4">
              <Card className="shadow-md">
                <CardHeader>
                  <CardTitle>Analyze Malware Report</CardTitle>
                  <CardDescription>
                    Upload a JSON report from a previous analysis to get detailed insights and recommendations.
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="flex flex-col items-center justify-center border-2 border-dashed rounded-lg p-8 bg-slate-50 dark:bg-slate-900/50">
                      <FileText className="h-10 w-10 text-muted-foreground mb-4" />
                      <h3 className="font-medium mb-2">Upload JSON Report</h3>
                      <p className="text-sm text-muted-foreground text-center mb-4">
                        Drag and drop your JSON report file here, or click to browse
                      </p>
                      <Button variant="outline" onClick={handleJsonAttachmentClick}>
                        <Paperclip className="h-4 w-4 mr-2" />
                        Select JSON File
                      </Button>
                      <input
                        type="file"
                        ref={jsonFileInputRef}
                        onChange={handleJsonFileChange}
                        accept=".json"
                        className="hidden"
                      />
                    </div>

                    {jsonData && (
                      <div className="space-y-4">
                        <div className="p-3 bg-slate-100 dark:bg-slate-800 rounded-md">
                          <div className="flex justify-between items-center mb-2">
                            <h4 className="font-medium">JSON Report Loaded</h4>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => setJsonData(null)}
                              className="h-8 px-2 text-muted-foreground"
                            >
                              <X className="h-4 w-4 mr-1" />
                              Clear
                            </Button>
                          </div>
                          <p className="text-sm text-muted-foreground">
                            {jsonData.filename || "Report"} is ready for analysis
                          </p>
                        </div>

                        <Button className="w-full" onClick={analyzeJsonReport} disabled={isLoading}>
                          {isLoading ? (
                            <>
                              <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                              Analyzing...
                            </>
                          ) : (
                            <>Analyze Report</>
                          )}
                        </Button>
                      </div>
                    )}

                    <Separator className="my-4" />

                    <div>
                      <h3 className="font-medium mb-2">How It Works</h3>
                      <ol className="space-y-2 text-sm text-muted-foreground list-decimal pl-5">
                        <li>Upload a JSON report file from a previous malware analysis</li>
                        <li>Our AI will analyze the report and provide detailed insights</li>
                        <li>Get actionable recommendations based on the findings</li>
                        <li>Ask follow-up questions in the chat to learn more</li>
                      </ol>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </div>
      </main>
    </div>
  )
}
