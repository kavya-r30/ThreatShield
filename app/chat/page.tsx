"use client"

import type React from "react"

import { useState, useRef, useEffect } from "react"
import Link from "next/link"
import { ArrowLeft, Send, Bot, User, Loader2, ShieldAlert } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Textarea } from "@/components/ui/textarea"
import { ScrollArea } from "@/components/ui/scroll-area"
import { askAI } from "@/lib/api"

interface Message {
  id: string
  role: "user" | "assistant"
  content: string
  timestamp: Date
}

export default function ChatPage() {
  const [messages, setMessages] = useState<Message[]>([
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
  const messagesEndRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    scrollToBottom()
  }, [messages])

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" })
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!input.trim() || isLoading) return

    const userMessage: Message = {
      id: Date.now().toString(),
      role: "user",
      content: input,
      timestamp: new Date(),
    }

    setMessages((prev) => [...prev, userMessage])
    setInput("")
    setIsLoading(true)

    try {
      const response = await askAI(input)

      const assistantMessage: Message = {
        id: (Date.now() + 1).toString(),
        role: "assistant",
        content: response,
        timestamp: new Date(),
      }

      setMessages((prev) => [...prev, assistantMessage])
    } catch (error) {
      console.error("Error getting AI response:", error)

      const errorMessage: Message = {
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

  return (
    <div className="flex min-h-screen flex-col">
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
            <ShieldAlert className="h-8 w-8 text-primary" />
            <div>
              <h1 className="text-3xl font-bold">ThreatShield AI Assistant</h1>
              <p className="text-muted-foreground">Ask questions about malware, threats, and cybersecurity</p>
            </div>
          </div>

          <Card className="mb-4">
            <CardHeader className="pb-3">
              <CardTitle>How can I help you?</CardTitle>
              <CardDescription>
                I can answer questions about malware types, explain analysis results, or provide security
                recommendations.
              </CardDescription>
            </CardHeader>
            <CardContent className="grid gap-2">
              <Button
                variant="outline"
                className="justify-start"
                onClick={() => setInput("What are the most common signs of malware in PE files?")}
              >
                What are the most common signs of malware in PE files?
              </Button>
              <Button
                variant="outline"
                className="justify-start"
                onClick={() => setInput("Explain what high entropy in file sections means")}
              >
                Explain what high entropy in file sections means
              </Button>
              <Button
                variant="outline"
                className="justify-start"
                onClick={() => setInput("How can I protect my system from ransomware?")}
              >
                How can I protect my system from ransomware?
              </Button>
            </CardContent>
          </Card>

          <Card className="mb-4 border-primary/20">
            <CardContent className="p-0">
              <ScrollArea className="h-[500px] p-4">
                <div className="space-y-4 pb-4">
                  {messages.map((message) => (
                    <div
                      key={message.id}
                      className={`flex ${message.role === "assistant" ? "justify-start" : "justify-end"}`}
                    >
                      <div
                        className={`flex gap-3 max-w-[80%] ${
                          message.role === "assistant" ? "bg-muted" : "bg-primary/10"
                        } p-3 rounded-lg`}
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
                      <div className="flex gap-3 max-w-[80%] bg-muted p-3 rounded-lg">
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

          <form onSubmit={handleSubmit} className="flex gap-2">
            <Textarea
              placeholder="Type your message here..."
              value={input}
              onChange={(e) => setInput(e.target.value)}
              className="min-h-[60px]"
              onKeyDown={(e) => {
                if (e.key === "Enter" && !e.shiftKey) {
                  e.preventDefault()
                  handleSubmit(e)
                }
              }}
            />
            <Button type="submit" size="icon" disabled={!input.trim() || isLoading}>
              <Send className="h-4 w-4" />
              <span className="sr-only">Send</span>
            </Button>
          </form>
        </div>
      </main>
    </div>
  )
}