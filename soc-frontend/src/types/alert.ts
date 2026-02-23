export type Severity = 'critical' | 'high' | 'medium' | 'low';
export type AlertStatus = 'new' | 'investigating' | 'contained' | 'closed';
export type AlertSource = 'EDR' | 'Firewall' | 'IDS' | 'SIEM' | 'Cloud' | 'Email';

export interface Alert {
    id: string;
    timestamp: string;
    type: string;
    source: AlertSource;
    severity: Severity;
    status: AlertStatus;
    ioc_confidence: number;
    asset_criticality: number;
    description: string;
    target: string;
    mitre_tactic?: string;
    mitre_technique?: string;
    raw_log?: string;
    iocs?: { type: string; value: string }[];
    metadata?: Record<string, unknown>;
}

export interface ResponseAction {
    id: string;
    type: 'block_ip' | 'isolate_host' | 'kill_process' | 'disable_user' | 'quarantine';
    target: string;
    status: 'pending' | 'approved' | 'executed' | 'failed';
    security_gain: number;
    operational_cost: number;
    business_risk: number;
}

export interface Incident {
    id: string;
    alert: Alert;
    recommended_actions: ResponseAction[];
    priority_score: number;
    blast_radius: number;
    resolved: boolean;
}

export interface Playbook {
    id: string;
    name: string;
    description: string;
    actions: string[];
    trigger_severity: Severity;
    dry_run: boolean;
    last_run?: string;
    status: 'ready' | 'running' | 'completed' | 'failed';
}

export interface AuditEntry {
    timestamp: string;
    actor: string;
    action: string;
    target: string;
    outcome: string;
    incident_id?: string;
}
