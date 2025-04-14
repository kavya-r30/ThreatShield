"use client"

import { ResponsiveContainer, PieChart as RechartsPieChart, Pie, Cell, Legend, Tooltip } from "recharts"
import { BarChart as RechartsBarChart, Bar, XAxis, YAxis, CartesianGrid } from "recharts"

interface ChartDataItem {
  name: string
  value: number
  color?: string
}

interface PieChartProps {
  data: ChartDataItem[]
  title?: string
  donut?: boolean
}

export function PieChart({ data, title, donut = false }: PieChartProps) {
  if (data.length === 0) {
    return <div className="flex items-center justify-center h-full">No data available</div>
  }

  return (
    <ResponsiveContainer width="100%" height="100%">
      <RechartsPieChart>
        <Pie
          data={data}
          cx="50%"
          cy="50%"
          innerRadius={donut ? 60 : 0}
          outerRadius={80}
          fill="#8884d8"
          paddingAngle={5}
          dataKey="value"
          label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
        >
          {data.map((entry, index) => (
            <Cell key={`cell-${index}`} fill={entry.color || `#${Math.floor(Math.random() * 16777215).toString(16)}`} />
          ))}
        </Pie>
        <Tooltip formatter={(value) => `${value}`} />
        <Legend />
      </RechartsPieChart>
    </ResponsiveContainer>
  )
}

interface BarChartProps {
  data: ChartDataItem[]
  title?: string
  xAxisLabel?: string
  yAxisLabel?: string
  vertical?: boolean
}

export function BarChart({ data, title, xAxisLabel, yAxisLabel, vertical = false }: BarChartProps) {
  if (data.length === 0) {
    return <div className="flex items-center justify-center h-full">No data available</div>
  }

  return (
    <ResponsiveContainer width="100%" height="100%">
      <RechartsBarChart
        data={data}
        layout={vertical ? "vertical" : "horizontal"}
        margin={{ top: 20, right: 30, left: 50, bottom: 20 }}
      >
        <CartesianGrid strokeDasharray="3 3" />
        {vertical ? (
          <>
            <XAxis type="number" />
            <YAxis type="category" dataKey="name" width={120} />
          </>
        ) : (
          <>
            <XAxis dataKey="name" />
            <YAxis />
          </>
        )}
        <Tooltip />
        <Legend />
        <Bar dataKey="value" name={title || "Value"}>
          {data.map((entry, index) => (
            <Cell key={`cell-${index}`} fill={entry.color || `#${Math.floor(Math.random() * 16777215).toString(16)}`} />
          ))}
        </Bar>
      </RechartsBarChart>
    </ResponsiveContainer>
  )
}
