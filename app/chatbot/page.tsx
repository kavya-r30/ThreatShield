"use client"

import type React from "react"

import { useState, useRef, useEffect } from "react"
import Link from "next/link"
import { ArrowLeft, Send, Bot, User, Loader2, ShieldAlert, Paperclip, X } from "lucide-react"
import { Card, CardContent } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Textarea } from "@/components/ui/textarea"
import { ScrollArea } from "@/components/ui/scroll-area"
import type { ChatMessage } from "@/lib/types"
import { cn } from "@/lib/utils"
import { generateChatResponse } from "@/lib/api"

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
  const fileInputRef = useRef<HTMLInputElement>(null)
  const messagesEndRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    scrollToBottom()
  }, [messages])

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" })
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
      const response = await generateChatResponse(input, attachment)

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

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      setAttachment(e.target.files[0])
    }
  }

  const handleAttachmentClick = () => {
    fileInputRef.current?.click()
  }

  const removeAttachment = () => {
    setAttachment(null)
    if (fileInputRef.current) {
      fileInputRef.current.value = ""
    }
  }

  const suggestedQuestions = [
    "What are the most common signs of malware in PE files?",
    "Explain what high entropy in file sections means",
    "How can I protect my system from ransomware?",
    "What does it mean when DllCharacteristics is set to 0?",
  ]

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
        <div className="max-w-4xl mx-auto">
          <div className="flex items-center gap-3 mb-6">
            <div className="rounded-full bg-primary/10 p-2">
              <ShieldAlert className="h-6 w-6 text-primary" />
            </div>
            <div>
              <h1 className="text-3xl font-bold tracking-tight">ThreatShield AI Assistant</h1>
              <p className="text-muted-foreground">Ask questions about malware, threats, and cybersecurity</p>
            </div>
          </div>

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
                    <Button type="button" variant="ghost" size="icon" className="h-6 w-6" onClick={removeAttachment}>
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
                        onClick={() => setInput(question)}
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
        </div>
      </main>
    </div>
  )
}
