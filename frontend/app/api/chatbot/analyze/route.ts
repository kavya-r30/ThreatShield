import { NextResponse } from "next/server"
import { generateText } from "ai"
import { openai } from "@ai-sdk/openai"

export async function POST(req: Request) {
  try {
    const analysisData = await req.json()

    if (!analysisData) {
      return NextResponse.json({ error: "No analysis data provided" }, { status: 400 })
    }

    // Generate a report using the AI SDK
    const { text: report } = await generateText({
      model: openai("gpt-4o"),
      prompt: `Analyze the following malware analysis report and provide a detailed explanation of the findings, potential threats, and recommendations:
      
      ${JSON.stringify(analysisData, null, 2)}`,
      system:
        "You are a cybersecurity expert specializing in malware analysis. Provide a detailed, technical analysis of the report data, explaining the significance of each finding, the potential threats, and specific recommendations for mitigation.",
      maxTokens: 1500,
    })

    // Generate a structured analysis
    const { text: structuredAnalysis } = await generateText({
      model: openai("gpt-4o"),
      prompt: `Analyze the following malware analysis report and provide a structured analysis with key findings, threat assessment, and recommendations:
      
      ${JSON.stringify(analysisData, null, 2)}`,
      system:
        "You are a cybersecurity expert. Provide a structured analysis in JSON format with these sections: keyFindings (array), threatAssessment (object with level and description), and recommendations (array).",
      maxTokens: 1000,
    })

    return NextResponse.json({
      status: "success",
      report,
      structured_analysis: structuredAnalysis,
    })
  } catch (error) {
    console.error("Error in chat/analyze route:", error)
    return NextResponse.json({ error: "Failed to analyze report" }, { status: 500 })
  }
}
