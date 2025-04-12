export enum FileType {
  PE = "pe",
  OFFICE = "office",
  PDF = "pdf",
  SCRIPT = "script",
  APK = "apk",
}

export enum RiskLevel {
  LOW = "low",
  MEDIUM = "medium",
  HIGH = "high",
  CRITICAL = "critical",
  INFO = "info",
}

export interface Feature {
  feature: string
  importance_score: number
}

export interface SuspiciousFeature {
  feature: string
  risk_level: RiskLevel
  value: number | string
  hex_value?: string
  description?: string
}

export interface Observation {
  finding: string
  description: string
  risk_level: RiskLevel
}

export interface DetailedFeature {
  feature_name: string
  value: number | string
  hex_value?: string
  readable_value?: string
  importance_score: number
  is_suspicious: boolean
  risk_level: RiskLevel
  category?: string
  entropy_category?: string
  base_category?: string
  observations: Observation[]
  flags?: string[]
}

export interface PEAnalysisResult {
  filename: string
  analysis_data: {
    summary: {
      prediction: string
      prediction_code: number
      confidence_score: number
      confidence_distribution: {
        legitimate: number
        malicious: number
      }
      threat_summary: string
    }
    features: {
      importance_ranking: Feature[]
      values: Record<string, number | string>
      suspicious_features: SuspiciousFeature[]
    }
    risk_metrics: {
      total_suspicious_features: number
      high_risk_features: number
      medium_risk_features: number
      low_risk_features: number
      risk_score: number
      risk_level: RiskLevel
    }
    detailed_analysis: DetailedFeature[]
  }
}

export interface Indicator {
  type: string
  details: string
  severity: string
}

export interface GeneralAnalysisResult {
  file_name: string
  file_type: string
  is_malicious: boolean
  confidence: number
  risk_level: string
  indicators: Indicator[]
  mitigations: string[]
  analysis_summary: string
}

export interface ScanHistoryItem {
  id: string
  fileName: string
  fileType: FileType
  scanDate: string
  result: "clean" | "malicious" | "suspicious" | "legitimate"
  riskScore: number
  threatCount: number
}
