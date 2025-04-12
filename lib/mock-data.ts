import type { PEAnalysisResult } from "./types"

export const mockPEAnalysisResult: PEAnalysisResult = {
  analysis_data: {
    summary: {
      prediction: "legitimate",
      prediction_code: 0,
      confidence_score: 58.0,
      confidence_distribution: {
        legitimate: 58.0,
        malicious: 42.0,
      },
      threat_summary: "Found 5 suspicious features with 5 high-risk indicators.",
    },
    features: {
      importance_ranking: [
        {
          feature: "DllCharacteristics",
          importance_score: 18.1,
        },
        {
          feature: "Machine",
          importance_score: 11.43,
        },
        {
          feature: "Characteristics",
          importance_score: 7.9,
        },
        {
          feature: "Subsystem",
          importance_score: 6.23,
        },
        {
          feature: "VersionInformationSize",
          importance_score: 6.03,
        },
        {
          feature: "SectionsMaxEntropy",
          importance_score: 6.02,
        },
        {
          feature: "ImageBase",
          importance_score: 5.9,
        },
        {
          feature: "ResourcesMaxEntropy",
          importance_score: 5.11,
        },
        {
          feature: "MajorSubsystemVersion",
          importance_score: 4.31,
        },
        {
          feature: "SizeOfOptionalHeader",
          importance_score: 4.18,
        },
        {
          feature: "MajorOperatingSystemVersion",
          importance_score: 2.73,
        },
        {
          feature: "ResourcesMinEntropy",
          importance_score: 2.16,
        },
        {
          feature: "SectionsMinEntropy",
          importance_score: 1.98,
        },
      ],
      values: {
        Characteristics: 783,
        DllCharacteristics: 0,
        ImageBase: 4194304,
        Machine: 332,
        MajorOperatingSystemVersion: 4,
        MajorSubsystemVersion: 4,
        ResourcesMaxEntropy: 7.910431870080642,
        ResourcesMinEntropy: 1.919240704636849,
        SectionsMaxEntropy: 7.988239112525155,
        SectionsMinEntropy: 0.0,
        SizeOfOptionalHeader: 224,
        Subsystem: 2,
        VersionInformationSize: 0,
      },
      suspicious_features: [
        {
          feature: "DllCharacteristics",
          hex_value: "0x0000",
          risk_level: "high",
          value: 0,
        },
        {
          description: "Relocations stripped",
          feature: "Characteristics",
          hex_value: "0x030f",
          risk_level: "high",
          value: 783,
        },
        {
          description: "Very high entropy indicates obfuscation",
          feature: "SectionsMaxEntropy",
          risk_level: "high",
          value: 7.99,
        },
        {
          description: "Very high resource entropy indicates hiding",
          feature: "ResourcesMaxEntropy",
          risk_level: "high",
          value: 7.91,
        },
        {
          description: "No version information",
          feature: "VersionInformationSize",
          risk_level: "high",
          value: 0,
        },
      ],
    },
    risk_metrics: {
      high_risk_features: 5,
      low_risk_features: 0,
      medium_risk_features: 0,
      risk_level: "high",
      risk_score: 100,
      total_suspicious_features: 5,
    },
    detailed_analysis: [
      {
        feature_name: "DllCharacteristics",
        hex_value: "0x0000",
        importance_score: 18.1,
        is_suspicious: true,
        observations: [
          {
            description: "This is suspicious as modern legitimate software typically uses ASLR",
            finding: "ASLR disabled",
            risk_level: "medium",
          },
          {
            description: "This is suspicious as modern legitimate software typically uses DEP",
            finding: "DEP/NX disabled",
            risk_level: "medium",
          },
          {
            description: "Unusual for modern legitimate software",
            finding: "No DLL characteristics set",
            risk_level: "high",
          },
        ],
        risk_level: "high",
        value: 0,
      },
      {
        feature_name: "Machine",
        hex_value: "0x014c",
        importance_score: 11.43,
        is_suspicious: false,
        observations: [
          {
            description: "Identifies the target CPU architecture",
            finding: "Target architecture: x86 (32-bit)",
            risk_level: "info",
          },
        ],
        readable_value: "x86 (32-bit)",
        risk_level: "low",
        value: 332,
      },
      {
        feature_name: "Characteristics",
        flags: ["EXECUTABLE_IMAGE", "RELOCS_STRIPPED"],
        hex_value: "0x030f",
        importance_score: 7.9,
        is_suspicious: true,
        observations: [
          {
            description: "Normal characteristic for executable files",
            finding: "File is executable",
            risk_level: "info",
          },
          {
            description: "Suspicious for modern software, often indicates manually modified PE",
            finding: "Relocations stripped",
            risk_level: "high",
          },
        ],
        risk_level: "high",
        value: 783,
      },
      {
        entropy_category: "Very High",
        feature_name: "SectionsMaxEntropy",
        importance_score: 6.02,
        is_suspicious: true,
        observations: [
          {
            description: "Indicates encryption, packing, or obfuscation",
            finding: "Very high section entropy (7.99)",
            risk_level: "high",
          },
        ],
        risk_level: "high",
        value: 7.99,
      },
      {
        base_category: "Standard",
        feature_name: "ImageBase",
        hex_value: "0x00400000",
        importance_score: 5.9,
        is_suspicious: false,
        observations: [
          {
            description: "Common legitimate base address",
            finding: "Standard base address for Windows executables",
            risk_level: "low",
          },
        ],
        risk_level: "low",
        value: 4194304,
      },
      {
        entropy_category: "Very High",
        feature_name: "ResourcesMaxEntropy",
        importance_score: 5.11,
        is_suspicious: true,
        observations: [
          {
            description: "May indicate encrypted data hidden in resources",
            finding: "Very high resource entropy (7.91)",
            risk_level: "high",
          },
        ],
        risk_level: "high",
        value: 7.91,
      },
      {
        category: "Common",
        feature_name: "Subsystem",
        importance_score: 6.23,
        is_suspicious: false,
        observations: [
          {
            description: "",
            finding: "Windows GUI",
            risk_level: "info",
          },
        ],
        readable_value: "Windows GUI",
        risk_level: "low",
        value: 2,
      },
      {
        category: "Missing",
        feature_name: "VersionInformationSize",
        importance_score: 6.03,
        is_suspicious: true,
        observations: [
          {
            description: "Common in malware to avoid identification",
            finding: "No version information",
            risk_level: "high",
          },
        ],
        risk_level: "high",
        value: 0,
      },
      {
        feature_name: "MajorSubsystemVersion",
        importance_score: 4.31,
        is_suspicious: false,
        observations: [
          {
            description: "No specific analysis available",
            finding: "MajorSubsystemVersion value: 4",
            risk_level: "info",
          },
        ],
        risk_level: "low",
        value: 4,
      },
      {
        feature_name: "SizeOfOptionalHeader",
        importance_score: 4.18,
        is_suspicious: false,
        observations: [
          {
            description: "No specific analysis available",
            finding: "SizeOfOptionalHeader value: 224",
            risk_level: "info",
          },
        ],
        risk_level: "low",
        value: 224,
      },
      {
        feature_name: "MajorOperatingSystemVersion",
        importance_score: 2.73,
        is_suspicious: false,
        observations: [
          {
            description: "No specific analysis available",
            finding: "MajorOperatingSystemVersion value: 4",
            risk_level: "info",
          },
        ],
        risk_level: "low",
        value: 4,
      },
      {
        feature_name: "ResourcesMinEntropy",
        importance_score: 2.16,
        is_suspicious: false,
        observations: [
          {
            description: "No specific analysis available",
            finding: "ResourcesMinEntropy value: 1.919240704636849",
            risk_level: "info",
          },
        ],
        risk_level: "low",
        value: 1.919240704636849,
      },
      {
        feature_name: "SectionsMinEntropy",
        importance_score: 1.98,
        is_suspicious: false,
        observations: [
          {
            description: "No specific analysis available",
            finding: "SectionsMinEntropy value: 0.0",
            risk_level: "info",
          },
        ],
        risk_level: "low",
        value: 0.0,
      },
    ],
  },
  filename: "mingw-get-setup.exe",
}
