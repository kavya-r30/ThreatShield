-- Create history table to store scan results
CREATE TABLE IF NOT EXISTS scan_history (
  id VARCHAR(36) PRIMARY KEY,
  file_name VARCHAR(255) NOT NULL,
  file_type VARCHAR(50) NOT NULL,
  scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  result VARCHAR(50) NOT NULL,
  risk_score INTEGER NOT NULL,
  threat_count INTEGER NOT NULL,
  file_hash VARCHAR(64),
  user_id VARCHAR(36),
  raw_result JSON,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create index for faster queries
CREATE INDEX IF NOT EXISTS idx_scan_history_file_type ON scan_history(file_type);
CREATE INDEX IF NOT EXISTS idx_scan_history_scan_date ON scan_history(scan_date);
CREATE INDEX IF NOT EXISTS idx_scan_history_result ON scan_history(result);
CREATE INDEX IF NOT EXISTS idx_scan_history_user_id ON scan_history(user_id);

-- Create view for recent scans
CREATE VIEW IF NOT EXISTS recent_scans AS
SELECT id, file_name, file_type, scan_date, result, risk_score, threat_count
FROM scan_history
ORDER BY scan_date DESC
LIMIT 100;

-- Create view for high risk scans
CREATE VIEW IF NOT EXISTS high_risk_scans AS
SELECT id, file_name, file_type, scan_date, result, risk_score, threat_count
FROM scan_history
WHERE risk_score > 75 OR result = 'malicious'
ORDER BY scan_date DESC;
