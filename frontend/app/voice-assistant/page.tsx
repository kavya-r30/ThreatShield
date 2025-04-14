"use client"

import { useState, useRef, useEffect } from "react"
import Link from "next/link"
import { ArrowLeft, Mic, MicOff, Bot, User, Loader2, ShieldAlert, Volume2, VolumeX, Send } from "lucide-react"
import { Card, CardContent } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Progress } from "@/components/ui/progress"
import { cn } from "@/lib/utils"
import { askAI } from "@/lib/api"
import type { ChatMessage } from "@/lib/types"

export default function VoiceAssistantPage() {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: "welcome",
      role: "assistant",
      content:
        "Hello! I'm your ThreatShield voice assistant. You can ask me questions about cybersecurity by clicking the microphone button. How can I help you today?",
      timestamp: new Date(),
    },
  ])
  const [isListening, setIsListening] = useState(false)
  const [transcript, setTranscript] = useState("")
  const [isLoading, setIsLoading] = useState(false)
  const [isSpeaking, setIsSpeaking] = useState(false)
  const [volume, setVolume] = useState(1)
  const messagesEndRef = useRef<HTMLDivElement>(null)

  const recognitionRef = useRef<any>(null)
  const utteranceRef = useRef<SpeechSynthesisUtterance | null>(null)

  useEffect(() => {
    if (typeof window !== "undefined") {
      const SpeechRecognition = window.SpeechRecognition || (window as any).webkitSpeechRecognition
      if (SpeechRecognition) {
        recognitionRef.current = new SpeechRecognition()
        recognitionRef.current.continuous = false
        recognitionRef.current.interimResults = true
        recognitionRef.current.lang = "en-US"

        recognitionRef.current.onresult = (event: any) => {
          const current = event.resultIndex
          const result = event.results[current]
          const transcriptValue = result[0].transcript
          setTranscript(transcriptValue)
        }

        recognitionRef.current.onend = () => {
          setIsListening(false)
        }

        recognitionRef.current.onerror = (event: any) => {
          console.error("Speech recognition error", event.error)
          setIsListening(false)
        }
      } else {
        console.error("Speech Recognition API not supported in this browser")
      }
    }

    return () => {
      if (recognitionRef.current) {
        recognitionRef.current.abort()
      }
      if (utteranceRef.current && window.speechSynthesis) {
        window.speechSynthesis.cancel()
      }
    }
  }, [])

  useEffect(() => {
    scrollToBottom()
  }, [messages])

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" })
  }

  const toggleListening = () => {
    if (isListening) {
      stopListening()
    } else {
      startListening()
    }
  }

  const startListening = () => {
    setTranscript("")
    setIsListening(true)
    recognitionRef.current?.start()
  }

  const stopListening = () => {
    recognitionRef.current?.stop()
    setIsListening(false)
  }

  const handleSendMessage = async () => {
    if (!transcript.trim()) return

    const userMessage: ChatMessage = {
      id: Date.now().toString(),
      role: "user",
      content: transcript,
      timestamp: new Date(),
    }

    setMessages((prev) => [...prev, userMessage])
    setIsLoading(true)

    try {
      const response = await askAI(transcript)

      const assistantMessage: ChatMessage = {
        id: (Date.now() + 1).toString(),
        role: "assistant",
        content: response,
        timestamp: new Date(),
      }

      setMessages((prev) => [...prev, assistantMessage])

      speakText(response)
    } catch (error) {
      console.error("Error getting AI response:", error)

      const errorMessage: ChatMessage = {
        id: (Date.now() + 1).toString(),
        role: "assistant",
        content: "I'm sorry, I encountered an error processing your request. Please try again later.",
        timestamp: new Date(),
      }

      setMessages((prev) => [...prev, errorMessage])

      speakText("I'm sorry, I encountered an error processing your request. Please try again later.")
    } finally {
      setIsLoading(false)
      setTranscript("")
    }
  }

  const speakText = (text: string) => {
    if ("speechSynthesis" in window) {
      window.speechSynthesis.cancel()

      utteranceRef.current = new SpeechSynthesisUtterance(text)

      utteranceRef.current.volume = volume

      utteranceRef.current.onstart = () => setIsSpeaking(true)
      utteranceRef.current.onend = () => setIsSpeaking(false)
      utteranceRef.current.onerror = (event) => {
        setIsSpeaking(false)
      }

      window.speechSynthesis.speak(utteranceRef.current)
    } else {
      console.error("Speech Synthesis API not supported in this browser")
    }
  }

  const toggleMute = () => {
    if (volume === 0) {
      setVolume(1)
      if (utteranceRef.current) {
        utteranceRef.current.volume = 1
      }
    } else {
      setVolume(0)
      if (utteranceRef.current) {
        utteranceRef.current.volume = 0
      }
    }

    // Cancel current speech if muting
    if (volume !== 0 && isSpeaking) {
      window.speechSynthesis.cancel()
      setIsSpeaking(false)
    }
  }

  const suggestedQuestions = [
    "What are the most common signs of malware?",
    "How can I protect my system from ransomware?",
    "What is a zero-day vulnerability?",
    "Explain what phishing attacks are",
    "What security measures should I implement for my home network?",
  ]

  const askSuggestedQuestion = (question: string) => {
    setTranscript(question)

    setTimeout(() => {
      const userMessage: ChatMessage = {
        id: Date.now().toString(),
        role: "user",
        content: question,
        timestamp: new Date(),
      }

      setMessages((prev) => [...prev, userMessage])
      setIsLoading(true)

      askAI(question)
        .then((response) => {
          const assistantMessage: ChatMessage = {
            id: (Date.now() + 1).toString(),
            role: "assistant",
            content: response,
            timestamp: new Date(),
          }

          setMessages((prev) => [...prev, assistantMessage])
          speakText(response)
        })
        .catch((error) => {
          console.error("Error getting AI response:", error)
          const errorMessage: ChatMessage = {
            id: (Date.now() + 1).toString(),
            role: "assistant",
            content: "I'm sorry, I encountered an error processing your request. Please try again later.",
            timestamp: new Date(),
          }
          setMessages((prev) => [...prev, errorMessage])
        })
        .finally(() => {
          setIsLoading(false)
          setTranscript("")
        })
    }, 500)
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
        <div className="max-w-4xl mx-auto">
          <div className="flex items-center gap-3 mb-6">
            <div className="rounded-full bg-primary/10 p-2">
              <ShieldAlert className="h-6 w-6 text-primary" />
            </div>
            <div>
              <h1 className="text-3xl font-bold tracking-tight">Voice Assistant</h1>
              <p className="text-muted-foreground">Ask cybersecurity questions using your voice</p>
            </div>
          </div>

          <div className="gap-6">
            <div>
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

              <div className="flex flex-col gap-4">
                {transcript && (
                  <div className="p-3 bg-slate-100 dark:bg-slate-800 rounded-lg">
                    <p className="text-sm font-medium mb-1">Transcript:</p>
                    <p className="text-sm">{transcript}</p>
                  </div>
                )}

                {isListening && (
                  <div className="flex items-center gap-2 mb-2">
                    <div className="flex-1">
                      <Progress value={100} className="h-2 animate-pulse" />
                    </div>
                    <span className="text-sm text-muted-foreground">Listening...</span>
                  </div>
                )}

                <div className="flex justify-center gap-4">
                  <Button
                    size="lg"
                    className={`rounded-full w-16 h-16 ${isListening ? "bg-red-500 hover:bg-red-600" : ""}`}
                    onClick={toggleListening}
                    disabled={isLoading}
                  >
                    {isListening ? <MicOff className="h-6 w-6" /> : <Mic className="h-6 w-6" />}
                    <span className="sr-only">{isListening ? "Stop Listening" : "Start Listening"}</span>
                  </Button>

                  <Button 
                    variant="outline" 
                    size="icon" 
                    className="rounded-full w-16 h-16" 
                    onClick={toggleMute}
                  >
                    {volume === 0 ? <VolumeX className="h-6 w-6" /> : <Volume2 className="h-6 w-6" />}
                    <span className="sr-only">{volume === 0 ? "Unmute" : "Mute"}</span>
                  </Button>

                  <Button
                    size="lg"
                    className="rounded-full w-16 h-16 bg-green-500 hover:bg-green-600"
                    onClick={handleSendMessage}
                    disabled={isLoading || !transcript.trim()}
                  >
                    <Send className="h-6 w-6" />
                    <span className="sr-only">Send Message</span>
                  </Button>
                </div>
              </div>
            </div>

            <div className="space-y-4 pt-4">
              <Card className="shadow-md">
                <CardContent className="p-4">
                  <h3 className="font-medium mb-3">Try Asking</h3>
                  <div className="space-y-2">
                    {suggestedQuestions.map((question, index) => (
                      <Button
                        key={index}
                        variant="outline"
                        className="w-full justify-start text-left h-auto py-2 px-3 text-sm"
                        onClick={() => askSuggestedQuestion(question)}
                        disabled={isLoading || isListening}
                      >
                        {question}
                      </Button>
                    ))}
                  </div>
                </CardContent>
              </Card>

              <Card className="shadow-md bg-primary/5 border-primary/20">
                <CardContent className="p-4">
                  <h3 className="font-medium mb-2">Voice Commands</h3>
                  <ul className="space-y-2 text-sm text-muted-foreground">
                    <li className="flex items-start gap-2">
                      <Mic className="h-4 w-4 mt-0.5 text-primary" />
                      <span>Click the mic button to start speaking</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <MicOff className="h-4 w-4 mt-0.5 text-primary" />
                      <span>Click again to stop recording your message</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <Send className="h-4 w-4 mt-0.5 text-primary" />
                      <span>Click the send button to process your question</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <Volume2 className="h-4 w-4 mt-0.5 text-primary" />
                      <span>Toggle the speaker to mute/unmute responses</span>
                    </li>
                  </ul>
                </CardContent>
              </Card>
            </div>
          </div>
        </div>
      </main>
    </div>
  )
}