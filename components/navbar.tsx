"use client"

import { useState } from "react"
import Link from "next/link"
import { usePathname } from "next/navigation"
import { ShieldAlert, Menu, BarChart2, History, Upload, Settings, MessageSquare, Mic } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Sheet, SheetContent, SheetTrigger } from "@/components/ui/sheet"
import { cn } from "@/lib/utils"

export default function Navbar() {
  const pathname = usePathname()
  const [open, setOpen] = useState(false)

  const routes = [
    {
      name: "Dashboard",
      path: "/dashboard",
      icon: <BarChart2 className="h-5 w-5" />,
    },
    {
      name: "Upload",
      path: "/",
      icon: <Upload className="h-5 w-5" />,
    },
    {
      name: "Chatbot",
      path: "/chat",
      icon: <MessageSquare className="h-5 w-5" />,
    },
    {
      name: "Voice Assistant",
      path: "/voice-assistant",
      icon: <Mic className="h-5 w-5" />,
    },
    {
      name: "History",
      path: "/history",
      icon: <History className="h-5 w-5" />,
    },
  ]

  return (
    <header className="sticky top-0 z-10 border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="container flex h-16 items-center justify-between">
        <div className="flex items-center gap-2">
          <Link href="/" className="flex items-center gap-2 font-semibold">
            <ShieldAlert className="h-6 w-6 text-primary" />
            <span className="text-xl font-bold">THREATSHIELD</span>
          </Link>
        </div>

        {/* Desktop Navigation */}
        <nav className="hidden md:flex items-center gap-6">
          {routes.map((route) => (
            <Link
              key={route.path}
              href={route.path}
              className={cn(
                "text-sm font-medium transition-colors flex items-center gap-1.5",
                pathname === route.path ? "text-primary" : "text-muted-foreground hover:text-primary",
              )}
            >
              {route.icon}
              {route.name}
            </Link>
          ))}
          <Button variant="default" size="sm" className="shadow-sm">
            Sign In
          </Button>
        </nav>

        {/* Mobile Navigation */}
        <Sheet open={open} onOpenChange={setOpen}>
          <SheetTrigger asChild className="md:hidden">
            <Button variant="ghost" size="icon">
              <Menu className="h-6 w-6" />
              <span className="sr-only">Toggle menu</span>
            </Button>
          </SheetTrigger>
          <SheetContent side="right" className="w-[250px] sm:w-[300px]">
            <div className="flex flex-col gap-6 mt-6">
              {routes.map((route) => (
                <Link
                  key={route.path}
                  href={route.path}
                  onClick={() => setOpen(false)}
                  className={cn(
                    "text-sm font-medium transition-colors flex items-center gap-2 p-2 rounded-md",
                    pathname === route.path
                      ? "text-primary bg-primary/10"
                      : "text-muted-foreground hover:text-primary hover:bg-muted",
                  )}
                >
                  {route.icon}
                  {route.name}
                </Link>
              ))}
              <Button className="mt-4">Sign In</Button>
            </div>
          </SheetContent>
        </Sheet>
      </div>
    </header>
  )
}
