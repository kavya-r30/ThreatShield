import Link from "next/link"
import FileUploadBox from "@/components/file-upload-box"
import { FileType } from "@/lib/types"
import { Shield, FileWarning, Zap } from "lucide-react"

export default function Home() {
  return (
    <div className="flex min-h-screen flex-col bg-gradient-to-b from-background to-slate-50 dark:from-background dark:to-slate-950/30">
      <main className="flex-1">
        <section className="w-full py-12 md:py-24">
          <div className="container px-4 md:px-6">
            <div className="flex flex-col items-center justify-center space-y-4 text-center">
              <div className="space-y-2 max-w-3xl">
                <h1 className="text-4xl font-bold tracking-tighter sm:text-5xl md:text-6xl bg-clip-text text-transparent bg-gradient-to-r from-primary to-primary/70">
                  Advanced Threat Detection
                </h1>
                <p className="mx-auto max-w-[700px] text-muted-foreground md:text-xl">
                  Protect your systems with our cutting-edge malware analysis platform. Upload files for instant threat
                  detection.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-8 w-full max-w-5xl">
                <div className="bg-white dark:bg-slate-900 rounded-xl shadow-md hover:shadow-lg transition-all p-6 border border-slate-200 dark:border-slate-800">
                  <div className="flex flex-col items-center p-6 text-center">
                    <div className="rounded-full bg-primary/10 p-3 mb-4">
                      <Shield className="h-8 w-8 text-primary" />
                    </div>
                    <h3 className="text-lg font-medium mb-2">Advanced Analysis</h3>
                    <p className="text-sm text-muted-foreground">
                      Our platform uses machine learning to detect even the most sophisticated threats.
                    </p>
                  </div>
                </div>

                <div className="bg-white dark:bg-slate-900 rounded-xl shadow-md hover:shadow-lg transition-all p-6 border border-slate-200 dark:border-slate-800">
                  <div className="flex flex-col items-center p-6 text-center">
                    <div className="rounded-full bg-primary/10 p-3 mb-4">
                      <FileWarning className="h-8 w-8 text-primary" />
                    </div>
                    <h3 className="text-lg font-medium mb-2">Multiple File Types</h3>
                    <p className="text-sm text-muted-foreground">
                      Analyze PE files, Office documents, PDFs, scripts, and APK files with detailed reports.
                    </p>
                  </div>
                </div>

                <div className="bg-white dark:bg-slate-900 rounded-xl shadow-md hover:shadow-lg transition-all p-6 border border-slate-200 dark:border-slate-800">
                  <div className="flex flex-col items-center p-6 text-center">
                    <div className="rounded-full bg-primary/10 p-3 mb-4">
                      <Zap className="h-8 w-8 text-primary" />
                    </div>
                    <h3 className="text-lg font-medium mb-2">AI-Powered Insights</h3>
                    <p className="text-sm text-muted-foreground">
                      Get expert explanations and recommendations from our AI assistant.
                    </p>
                  </div>
                </div>
              </div>

              <div className="w-full max-w-5xl mx-auto mt-12">
                <h2 className="text-2xl font-bold mb-6">Upload a File for Analysis</h2>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
                  <FileUploadBox type={FileType.PE} title="PE Files" description="DLL, EXE, etc." active={true} />
                  <FileUploadBox
                    type={FileType.OFFICE}
                    title="Office Documents"
                    description="DOCX, DOC, CSV, XLS, PPT"
                    active={true}
                  />
                  <FileUploadBox
                    type={FileType.PDF}
                    title="PDF Files"
                    description="Adobe PDF documents"
                    active={true}
                  />
                  <FileUploadBox
                    type={FileType.SCRIPT}
                    title="Script Files"
                    description="BAT, PS1, etc."
                    active={true}
                  />
                  <FileUploadBox type={FileType.APK} title="Android Apps" description="APK files" active={true} />
                </div>
              </div>
            </div>
          </div>
        </section>
      </main>
      <footer className="border-t py-6 bg-slate-50 dark:bg-slate-950/50">
        <div className="container flex flex-col items-center justify-center gap-4 md:flex-row md:gap-8">
          <p className="text-center text-sm text-muted-foreground">
            &copy; {new Date().getFullYear()} ThreatShield. All rights reserved.
          </p>
          <div className="flex gap-4">
            <Link href="/terms" className="text-sm text-muted-foreground hover:text-primary transition-colors">
              Terms
            </Link>
            <Link href="/privacy" className="text-sm text-muted-foreground hover:text-primary transition-colors">
              Privacy
            </Link>
          </div>
        </div>
      </footer>
    </div>
  )
}
