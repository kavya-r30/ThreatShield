import { NextResponse } from "next/server"
import { generateText } from "ai"
import { groq } from "@ai-sdk/groq"
import { createRetriever } from "@langchain/core/retrievers/remote"
import { StringOutputParser } from "@langchain/core/output_parsers"
import { RunnableSequence } from "@langchain/core/runnables"
import { PromptTemplate } from "@langchain/core/prompts"

// Create a retriever for the RAG system
const retriever = createRetriever({
  url: process.env.RETRIEVER_URL || "https://api.example.com/retrieve", // Replace with your actual retriever URL in production
  auth: { bearer: process.env.RETRIEVER_API_KEY || "" },
  inputKey: "query",
  outputKey: "documents",
})

// Define the prompt template for the RAG system
const promptTemplate = PromptTemplate.fromTemplate(`
You are a cybersecurity expert specializing in malware analysis and threat detection.
Answer the user's question based on the following context and your knowledge.
If the question cannot be answered based on the context, use your knowledge to provide a helpful response.

Context:
{context}

User Question: {question}

Your response should be informative, accurate, and helpful. If you're unsure, acknowledge the limitations.
`)

export async function POST(req: Request) {
  try {
    const { question } = await req.json()

    // In a real implementation, we would use the retriever to get relevant documents
    // For demo purposes, we'll simulate this with a try/catch
    let context = ""
    try {
      // Retrieve relevant documents from the vector store
      const docs = await retriever.invoke(question)
      context = docs.map((doc: any) => doc.pageContent).join("\n\n")
    } catch (error) {
      console.error("Error retrieving documents:", error)
      // If retrieval fails, use an empty context
      context = "No specific context available for this query."
    }

    // Create a chain that combines the retriever, prompt template, and LLM
    const chain = RunnableSequence.from([
      {
        context: async () => context,
        question: (input: { question: string }) => input.question,
      },
      promptTemplate,
      // Use Groq's Qwen model for generating the response
      async (prompt: string) => {
        const { text } = await generateText({
          model: groq("llama3-8b-8192"), // Using Llama3 as a fallback since Qwen wasn't specified in the model list
          prompt,
          system:
            "You are a cybersecurity expert specializing in malware analysis. Provide accurate, helpful information about threats, vulnerabilities, and security best practices.",
        })
        return text
      },
      new StringOutputParser(),
    ])

    // Execute the chain
    const response = await chain.invoke({ question })

    return NextResponse.json({ response })
  } catch (error) {
    console.error("Error in chat route:", error)
    return NextResponse.json({ error: "Failed to process your request" }, { status: 500 })
  }
}
