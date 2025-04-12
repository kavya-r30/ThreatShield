"use client"

import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, LabelList } from "recharts"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import type { PEAnalysisResult } from "@/lib/types"
import { Badge } from "@/components/ui/badge"
import { BarChartIcon as ChartBar } from "lucide-react"

interface FeaturesTabProps {
  data: PEAnalysisResult
}

export default function FeaturesTab({ data }: FeaturesTabProps) {
  const { analysis_data } = data

  // Transform data for chart - top 8 features by importance
  const importantFeatures = [...analysis_data.features.importance_ranking]
    .sort((a, b) => b.importance_score - a.importance_score)
    .slice(0, 8)
    .map((feature) => ({
      name: feature.feature,
      score: Number.parseFloat(feature.importance_score.toFixed(2)),
      value: analysis_data.features.values[feature.feature],
    }))

  return (
    <div className="grid gap-6">
      <Card className="shadow-md">
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-2">
            <ChartBar className="h-5 w-5 text-primary" />
            <span>Feature Importance</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="h-80">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={importantFeatures} layout="vertical" margin={{ top: 20, right: 30, left: 50, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" horizontal={true} vertical={false} />
                <XAxis type="number" />
                <YAxis type="category" dataKey="name" tick={{ fontSize: 12 }} width={120} />
                <Tooltip
                  formatter={(value, name, props) => {
                    if (name === "score") return [`${value}`, "Importance Score"]
                    return [value, name]
                  }}
                />
                <Bar dataKey="score" fill="#ef4444" radius={[0, 4, 4, 0]}>
                  <LabelList dataKey="score" position="right" formatter={(value: number) => value.toFixed(2)} />
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </CardContent>
      </Card>

      <Card className="shadow-md">
        <CardHeader className="pb-2">
          <CardTitle>Key Features and Values</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {importantFeatures.map((feature, index) => {
              const detailedFeature = analysis_data.detailed_analysis.find((f) => f.feature_name === feature.name)

              const isSuspicious = detailedFeature?.is_suspicious
              const riskLevel = detailedFeature?.risk_level

              return (
                <div
                  key={index}
                  className={`p-4 rounded-lg border ${
                    isSuspicious
                      ? riskLevel === "high"
                        ? "border-red-200 bg-red-50"
                        : "border-yellow-200 bg-yellow-50"
                      : "border"
                  } shadow-sm`}
                >
                  <div className="flex justify-between items-start mb-2">
                    <div className="font-medium">{feature.name}</div>
                    {isSuspicious && (
                      <Badge
                        className={`
                          ${
                            riskLevel === "high"
                              ? "bg-red-100 text-red-800 hover:bg-red-100"
                              : riskLevel === "medium"
                                ? "bg-yellow-100 text-yellow-800 hover:bg-yellow-100"
                                : "bg-blue-100 text-blue-800 hover:bg-blue-100"
                          }
                        `}
                      >
                        {riskLevel === "high" ? "High Risk" : riskLevel === "medium" ? "Medium Risk" : "Low Risk"}
                      </Badge>
                    )}
                  </div>
                  <div className="flex flex-col gap-1">
                    <div className="text-sm">
                      <span className="text-muted-foreground">Value: </span>
                      <span className="font-mono">{feature.value}</span>
                    </div>
                    <div className="text-sm">
                      <span className="text-muted-foreground">Importance: </span>
                      <span>{feature.score.toFixed(2)}</span>
                    </div>
                    {detailedFeature?.hex_value && (
                      <div className="text-sm">
                        <span className="text-muted-foreground">Hex: </span>
                        <span className="font-mono">{detailedFeature.hex_value}</span>
                      </div>
                    )}
                    {detailedFeature?.readable_value && (
                      <div className="text-sm">
                        <span className="text-muted-foreground">Description: </span>
                        <span>{detailedFeature.readable_value}</span>
                      </div>
                    )}
                  </div>
                </div>
              )
            })}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
