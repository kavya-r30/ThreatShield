import { NextResponse } from "next/server"
import { generateText } from "ai"
import { openai } from "@ai-sdk/openai"

export async function POST(req: Request) {
  try {
    const data = await req.json()

    if (!data || !data.question) {
      return NextResponse.json({ error: "No question provided" }, { status: 400 })
    }

    const question = data.question

    // Generate a response using the AI SDK
    const { text: response } = await generateText({
      model: openai("gpt-4o"),
      prompt: question,
      system:
        "You are a cybersecurity expert specializing in malware analysis and threat detection. Provide accurate, helpful information about threats, vulnerabilities, and security best practices. Your responses should be informative, technically accurate, and tailored to the user's level of expertise.",
      maxTokens: 1000,
    })

    return NextResponse.json({
      status: "success",
      question,
      response,
    })
  } catch (error) {
    console.error("Error in chat/ask route:", error)
    return NextResponse.json({ error: "Failed to process your request" }, { status: 500 })
  }
}
