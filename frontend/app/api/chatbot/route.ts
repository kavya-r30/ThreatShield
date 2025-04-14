import { NextResponse } from "next/server"
import { generateText } from "ai"
import { openai } from "@ai-sdk/openai"

export async function POST(req: Request) {
  try {
    const formData = await req.formData()
    const message = formData.get("message") as string
    const file = formData.get("file") as File | null

    let fileContent = ""
    if (file) {
      // Read the file content
      const buffer = await file.arrayBuffer()
      fileContent = new TextDecoder().decode(buffer)
    }

    // Construct the prompt based on whether there's a file or not
    let prompt = message || "Help me understand this file"

    if (fileContent) {
      prompt = `${prompt}\n\nFile content:\n${fileContent}`
    }

    // Generate a response using the AI SDK
    const { text } = await generateText({
      model: openai("gpt-4o"),
      prompt,
      system:
        "You are a cybersecurity expert specializing in malware analysis and threat detection. Provide accurate, helpful information about threats, vulnerabilities, and security best practices. If the user has uploaded a file, analyze its content and provide insights.",
      maxTokens: 1000,
    })

    return NextResponse.json({ response: text })
  } catch (error) {
    console.error("Error in chatbot route:", error)
    return NextResponse.json({ error: "Failed to process your request" }, { status: 500 })
  }
}
