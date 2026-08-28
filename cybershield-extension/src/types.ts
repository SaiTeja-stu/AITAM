// Mirrors the backend AnalyzeResponse.

export type RiskLevel = 'SAFE' | 'SUSPICIOUS' | 'HIGH_RISK' | 'MALICIOUS';

export interface Signal {
  policyId: string;
  name: string;
  detail: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'TRUST';
  weight: number;
}

export interface PaymentInfo {
  scheme: string;
  action: string;
  payeeVpa: string | null;
  payeeName: string | null;
  amount: number | null;
  currency: string | null;
  note: string | null;
  pullPayment: boolean;
}

export interface AnalyzeResponse {
  reportId: string;
  contentType: string;
  riskScore: number;
  riskLevel: RiskLevel;
  priority: string;
  wording: string;
  confidence: number;
  verified: boolean;
  trusted: boolean;
  initiatesPayment: boolean;
  categories: string[];
  signals: Signal[];
  explanation: string;
  recommendations: string[];
  payment: PaymentInfo | null;
  analyzedAt: string;
}

export type ContentType = 'URL' | 'EMAIL' | 'SMS' | 'QR' | 'WEBPAGE' | 'SOCIAL';

export interface AnalyzeRequest {
  type: ContentType;
  content: string;
  pageUrl?: string;
  source?: string;
}

// content-script <-> popup/background messages
export type CsMessage =
  | { kind: 'GET_PAGE_CONTEXT' }
  | { kind: 'GET_SELECTION' };

export interface PageContext {
  url: string;
  title: string;
  html: string;        // capped
  selection: string;
  linkCount: number;
}
