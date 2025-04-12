"use client"

import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from "recharts"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import type { PEAnalysisResult } from "@/lib/types"
import { Badge } from "@/components/ui/badge"
import { AlertCircle } from "lucide-react"

interface SummaryTabProps {
  data: PEAnalysisResult
}

export default function SummaryTab({ data }: SummaryTabProps) {
  const { analysis_data } = data
  const { summary, risk_metrics } = analysis_data

  const confidenceData = [
    { name: "Legitimate", value: summary.confidence_distribution.legitimate },
    { name: "Malicious", value: summary.confidence_distribution.malicious },
  ]

  const riskMetricsData = [
    { name: "High Risk", value: risk_metrics.high_risk_features },
    { name: "Medium Risk", value: risk_metrics.medium_risk_features },
    { name: "Low Risk", value: risk_metrics.low_risk_features },
  ]

  const CONFIDENCE_COLORS = ["#10b981", "#ef4444"]
  const RISK_COLORS = ["#ef4444", "#f59e0b", "#10b981"]

  return (
    <div className="grid gap-6">
      <div className="grid md:grid-cols-2 gap-6">
        <Card className="shadow-md">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Confidence Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={confidenceData}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={80}
                    fill="#8884d8"
                    paddingAngle={5}
                    dataKey="value"
                    label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                  >
                    {confidenceData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={CONFIDENCE_COLORS[index % CONFIDENCE_COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip formatter={(value) => `${value}%`} />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>

        <Card className="shadow-md">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Risk Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={riskMetricsData}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={80}
                    fill="#8884d8"
                    paddingAngle={5}
                    dataKey="value"
                    label={({ name, value }) => `${name}: ${value}`}
                  >
                    {riskMetricsData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={RISK_COLORS[index % RISK_COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card className="shadow-md">
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-2">
            <AlertCircle className="h-5 w-5 text-red-500" />
            <span>Suspicious Features Overview</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {analysis_data.features.suspicious_features.map((feature, index) => (
              <div key={index} className="border-b pb-3 last:border-0 last:pb-0">
                <div className="flex justify-between items-start">
                  <div>
                    <h4 className="font-medium">{feature.feature}</h4>
                    <p className="text-sm text-muted-foreground">{feature.description}</p>
                  </div>
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
                </div>
                <div className="mt-1 flex items-center gap-2 text-sm">
                  <span className="font-mono bg-muted px-1 py-0.5 rounded text-xs">Value: {feature.value}</span>
                  {feature.hex_value && (
                    <span className="font-mono bg-muted px-1 py-0.5 rounded text-xs">Hex: {feature.hex_value}</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
