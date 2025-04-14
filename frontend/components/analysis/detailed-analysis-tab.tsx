"use client"

import { useState } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import type { PEAnalysisResult } from "@/lib/types"
import { Badge } from "@/components/ui/badge"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import { ChevronDown, ChevronUp, AlertTriangle, Info, CheckCircle } from "lucide-react"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"

interface DetailedAnalysisTabProps {
  data: PEAnalysisResult
}

export default function DetailedAnalysisTab({ data }: DetailedAnalysisTabProps) {
  const [openItems, setOpenItems] = useState<Record<string, boolean>>({})
  const { analysis_data } = data

  const toggleItem = (key: string) => {
    setOpenItems((prev) => ({
      ...prev,
      [key]: !prev[key],
    }))
  }

  // Sort features by importance score
  const sortedFeatures = [...analysis_data.detailed_analysis].sort((a, b) => b.importance_score - a.importance_score)

  const getRiskIcon = (riskLevel: string) => {
    switch (riskLevel) {
      case "high":
        return <AlertTriangle className="h-4 w-4 text-red-500" />
      case "medium":
        return <AlertTriangle className="h-4 w-4 text-yellow-500" />
      case "low":
        return <Info className="h-4 w-4 text-blue-500" />
      default:
        return <CheckCircle className="h-4 w-4 text-green-500" />
    }
  }

  return (
    <div>
      <Card className="shadow-md">
        <CardHeader className="pb-2">
          <CardTitle>Detailed Feature Analysis</CardTitle>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-[600px] pr-4">
            <div className="space-y-4">
              {sortedFeatures.map((feature, index) => (
                <Collapsible
                  key={index}
                  open={openItems[feature.feature_name] || false}
                  onOpenChange={() => toggleItem(feature.feature_name)}
                  className={`border rounded-lg shadow-sm ${feature.is_suspicious ? (feature.risk_level === "high" ? "border-red-200" : "border-yellow-200") : "border-slate-200"}`}
                >
                  <CollapsibleTrigger className="flex w-full items-center justify-between p-4 text-left">
                    <div className="flex items-center gap-2">
                      <div>{getRiskIcon(feature.risk_level)}</div>
                      <div>
                        <div className="font-medium">{feature.feature_name}</div>
                        <div className="text-sm text-muted-foreground">
                          Importance: {feature.importance_score.toFixed(2)}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {feature.is_suspicious && (
                        <Badge
                          className={`
                            ${
                              feature.risk_level === "high"
                                ? "bg-red-100 text-red-800 hover:bg-red-100"
                                : feature.risk_level === "medium"
                                  ? "bg-yellow-100 text-yellow-800 hover:bg-yellow-100"
                                  : "bg-blue-100 text-blue-800 hover:bg-blue-100"
                            }
                          `}
                        >
                          {feature.risk_level === "high"
                            ? "High Risk"
                            : feature.risk_level === "medium"
                              ? "Medium Risk"
                              : "Low Risk"}
                        </Badge>
                      )}
                      {openItems[feature.feature_name] ? (
                        <ChevronUp className="h-4 w-4" />
                      ) : (
                        <ChevronDown className="h-4 w-4" />
                      )}
                    </div>
                  </CollapsibleTrigger>
                  <CollapsibleContent>
                    <div className="p-4 pt-0 border-t">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                        <div>
                          <div className="text-sm text-muted-foreground">Value</div>
                          <div className="font-mono">{feature.value}</div>
                        </div>
                        {feature.hex_value && (
                          <div>
                            <div className="text-sm text-muted-foreground">Hex Value</div>
                            <div className="font-mono">{feature.hex_value}</div>
                          </div>
                        )}
                        {feature.readable_value && (
                          <div>
                            <div className="text-sm text-muted-foreground">Readable Value</div>
                            <div>{feature.readable_value}</div>
                          </div>
                        )}
                        {feature.category && (
                          <div>
                            <div className="text-sm text-muted-foreground">Category</div>
                            <div>{feature.category}</div>
                          </div>
                        )}
                      </div>

                      {feature.observations && feature.observations.length > 0 && (
                        <div>
                          <div className="text-sm font-medium mb-2">Observations</div>
                          <Table>
                            <TableHeader>
                              <TableRow>
                                <TableHead>Finding</TableHead>
                                <TableHead>Description</TableHead>
                                <TableHead className="w-[120px]">Risk Level</TableHead>
                              </TableRow>
                            </TableHeader>
                            <TableBody>
                              {feature.observations.map((observation, obsIndex) => (
                                <TableRow key={obsIndex}>
                                  <TableCell className="font-medium">{observation.finding}</TableCell>
                                  <TableCell>{observation.description}</TableCell>
                                  <TableCell>
                                    <Badge
                                      className={`
                                        ${
                                          observation.risk_level === "high"
                                            ? "bg-red-100 text-red-800 hover:bg-red-100"
                                            : observation.risk_level === "medium"
                                              ? "bg-yellow-100 text-yellow-800 hover:bg-yellow-100"
                                              : observation.risk_level === "info"
                                                ? "bg-slate-100 text-slate-800 hover:bg-slate-100"
                                                : "bg-blue-100 text-blue-800 hover:bg-blue-100"
                                        }
                                      `}
                                    >
                                      {observation.risk_level}
                                    </Badge>
                                  </TableCell>
                                </TableRow>
                              ))}
                            </TableBody>
                          </Table>
                        </div>
                      )}

                      {feature.flags && feature.flags.length > 0 && (
                        <div className="mt-4">
                          <div className="text-sm font-medium mb-2">Flags</div>
                          <div className="flex flex-wrap gap-2">
                            {feature.flags.map((flag, flagIndex) => (
                              <Badge key={flagIndex} variant="outline">
                                {flag}
                              </Badge>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              ))}
            </div>
          </ScrollArea>
        </CardContent>
      </Card>
    </div>
  )
}
