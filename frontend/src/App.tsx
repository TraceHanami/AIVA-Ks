import React, { useState, useEffect, useMemo, useCallback } from 'react'

import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  MarkerType,
  Handle,
  Position,
  type Node,
  type Edge,
} from '@xyflow/react'
import {
  ShieldAlert,
  Activity,
  Terminal,
  Cpu,
  Zap,
  CheckCircle2,
  XCircle,
  Send,
  Lock,
  Layers,
  Search,
  Eye,
  FileText,
  Sparkles,
  Download,
  RefreshCw,
  HardDrive,
  Globe,
  Radio,
  FileCode,
  Check,
} from 'lucide-react'


// --- Types ---
interface GraphNodeData extends Record<string, unknown> {
  label: string
  nodeType: string
  risk: number
  metadata: Record<string, any>
  isSelected?: boolean
}

interface MitreMatch {
  technique_id: string
  name: string
  tactic: string
  confidence: number
  description: string
  evidence: string[]
}

interface TimelineEvent {
  timestamp: string
  event_type: string
  pid: number
  comm: string
  anomaly_score: number
  details: Record<string, any>
}

interface Action {
  action_id: string
  policy_name: string
  action_type: string
  target: Record<string, any>
  mode: string
  requires_approval: boolean
  status: string
  created_at: string
}

interface AuditEntry {
  id: string
  timestamp: string
  actor: string
  action_id: string
  action_type: string
  target: Record<string, any>
  status: string
  details: string
}

interface HeatmapArea {
  score: number
  peak_node?: string
  peak_risk?: number
  node_count?: number
}

interface DashboardData {
  host_id: string
  overall_risk: number
  threat_heatmap: Record<string, HeatmapArea | number>
  mitre_matches: MitreMatch[]
  narrative: string
  timeline_summary: string
  timeline_events: TimelineEvent[]
  graph: {
    nodes: Array<{
      id: string
      type: string
      label: string
      risk: number
      metadata: Record<string, any>
    }>
    edges: Array<{
      id: string
      source: string
      target: string
      relation: string
      weight: number
    }>
  }
  response_actions: Action[]
  audit_log: AuditEntry[]
  stats: {
    node_count: number
    edge_count: number
    total_events: number
    mitre_count: number
    pending_approvals: number
  }
}

interface ChatMessage {
  id: string
  role: 'user' | 'assistant'
  content: string
  timestamp: string
}

// --- Custom React Flow Node Component for Analysts ---
const SOCNodeComponent = ({ data }: { data: GraphNodeData }) => {
  const isHigh = data.risk >= 0.7
  const isMed = data.risk >= 0.3 && data.risk < 0.7

  const getIcon = () => {
    switch (data.nodeType?.toLowerCase()) {
      case 'process':
        return <Cpu className="h-4 w-4 text-purple-400" />
      case 'socket':
        return <Globe className="h-4 w-4 text-cyan-400" />
      case 'file':
        return <FileCode className="h-4 w-4 text-emerald-400" />
      case 'memory':
      case 'memoryregion':
        return <HardDrive className="h-4 w-4 text-amber-400" />
      default:
        return <Radio className="h-4 w-4 text-slate-400" />
    }
  }

  return (
    <div
      className={`px-3.5 py-2.5 rounded-xl border shadow-xl backdrop-blur-md min-w-[170px] transition-all duration-200 cursor-pointer ${
        data.isSelected
          ? 'bg-slate-900/95 border-cyan-400 ring-2 ring-cyan-400/50 shadow-cyan-950/50 scale-105'
          : isHigh
          ? 'bg-[#1e1014]/90 border-red-500/60 hover:border-red-400 shadow-red-950/40 hover:scale-[1.02]'
          : isMed
          ? 'bg-[#1e180e]/90 border-amber-500/60 hover:border-amber-400 shadow-amber-950/40 hover:scale-[1.02]'
          : 'bg-slate-900/80 border-slate-700/80 hover:border-slate-500 hover:scale-[1.02]'
      }`}
    >
      <Handle type="target" position={Position.Top} className="!bg-cyan-400 !w-2.5 !h-2.5 !border-2 !border-slate-900" />
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-1.5 min-w-0">
          <div className="p-1 rounded bg-slate-950/60 border border-slate-800/80">{getIcon()}</div>
          <span className="text-[11px] font-mono font-semibold uppercase tracking-wider text-slate-300 truncate">
            {data.nodeType}
          </span>
        </div>
        <span
          className={`text-[11px] font-mono font-bold px-2 py-0.5 rounded-full ${
            isHigh
              ? 'bg-red-500/20 text-red-400 border border-red-500/30'
              : isMed
              ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
              : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
          }`}
        >
          {Math.round(data.risk * 100)}%
        </span>
      </div>
      <div className="text-xs font-semibold font-mono text-slate-100 mt-2 truncate max-w-[170px]" title={data.label}>
        {data.label}
      </div>
      <Handle type="source" position={Position.Bottom} className="!bg-cyan-400 !w-2.5 !h-2.5 !border-2 !border-slate-900" />
    </div>
  )
}

const nodeTypes = { socNode: SOCNodeComponent }

export default function App() {
  const [hostMode, setHostMode] = useState<'live' | 'test'>('live')
  const [data, setData] = useState<DashboardData | null>(null)
  const [activeTab, setActiveTab] = useState<'workbench' | 'mitre' | 'forensics' | 'response' | 'copilot'>('workbench')
  const [selectedNode, setSelectedNode] = useState<any | null>(null)
  const [loading, setLoading] = useState(true)
  const [simulating, setSimulating] = useState(false)
  const [timelineFilter, setTimelineFilter] = useState('')
  const [minRiskFilter, setMinRiskFilter] = useState(0)

  // React Flow state
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([])
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([])

  // Copilot state
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([])
  const [chatInput, setChatInput] = useState('')
  const [chatLoading, setChatLoading] = useState(false)

  const fetchDashboard = useCallback(async () => {
    try {
      const res = await fetch(`/api/dashboard/summary?host=${hostMode}`)
      if (res.ok) {
        const json: DashboardData = await res.json()
        setData(json)

        // Convert backend graph into ReactFlow layout with clean staggered positioning
        const rfNodes: Node[] = json.graph.nodes.map((node, index) => {
          const col = index % 3
          const row = Math.floor(index / 3)
          return {
            id: node.id,
            type: 'socNode',
            position: { x: 50 + col * 260, y: 50 + row * 130 },
            data: {
              label: node.label,
              nodeType: node.type,
              risk: node.risk,
              metadata: node.metadata,
              isSelected: selectedNode?.id === node.id,
            },
          }
        })

        const rfEdges: Edge[] = json.graph.edges.map((edge) => ({
          id: edge.id,
          source: edge.source,
          target: edge.target,
          label: edge.relation,
          labelStyle: { fill: '#cbd5e1', fontSize: 11, fontFamily: 'monospace', fontWeight: 600 },
          labelBgStyle: { fill: '#0f172a', fillOpacity: 0.95 },
          labelBgPadding: [6, 3],
          labelBgBorderRadius: 6,
          animated: edge.weight > 0.5,
          markerEnd: { type: MarkerType.ArrowClosed, color: edge.weight > 0.5 ? '#f43f5e' : '#38bdf8', width: 14, height: 14 },
          style: { stroke: edge.weight > 0.5 ? '#f43f5e' : '#0284c7', strokeWidth: edge.weight > 0.5 ? 2.5 : 1.8 },
        }))

        setNodes(rfNodes)
        setEdges(rfEdges)

        setSelectedNode((prev: any) => {
          if (!prev && json.graph.nodes.length > 0) {
            return [...json.graph.nodes].sort((a, b) => b.risk - a.risk)[0]
          }
          return prev
        })
      }
    } catch (e) {
      console.error('Error fetching security telemetry:', e)
    } finally {
      setLoading(false)
    }
  }, [hostMode, selectedNode?.id, setNodes, setEdges])

  const fetchChatHistory = useCallback(async () => {
    try {
      const res = await fetch(`/api/copilot/history?host=${hostMode}`)
      if (res.ok) {
        const json = await res.json()
        setChatMessages(json.history || [])
      }
    } catch (e) {
      console.error('Error fetching copilot history:', e)
    }
  }, [hostMode])

  useEffect(() => {
    fetchDashboard()
    fetchChatHistory()
    const interval = setInterval(fetchDashboard, 1000)
    return () => clearInterval(interval)
  }, [fetchDashboard, fetchChatHistory])


  const onNodeClick = (_: any, node: Node) => {
    const rawNode = data?.graph.nodes.find((n) => n.id === node.id)
    if (rawNode) {
      setSelectedNode(rawNode)
      setNodes((nds) =>
        nds.map((n) => ({
          ...n,
          data: {
            ...n.data,
            isSelected: n.id === node.id,
          },
        }))
      )
    }
  }

  const handleApproveAction = async (actionId: string, approved: boolean) => {
    try {
      await fetch(`/api/actions/approve?host=${hostMode}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action_id: actionId, approver: 'Lead_SOC_Analyst_G1', approved }),
      })
      await fetchDashboard()
    } catch (e) {
      console.error('Failed to submit containment decision:', e)
    }
  }

  const handleInjectTelemetry = async () => {
    setSimulating(true)
    const event = {
      event_type: 'sys_enter_connect',
      pid: 4260,
      comm: 'powershell',
      target_ip: '198.51.100.22',
      target_port: 8443,
      anomaly_score: 0.96,
    }
    await fetch(`/api/events/ingest?host=${hostMode}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(event),
    })
    await fetchDashboard()
    setSimulating(false)
  }

  const handleSendChat = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!chatInput.trim() || chatLoading) return

    const question = chatInput
    setChatInput('')
    setChatLoading(true)

    setChatMessages((prev) => [
      ...prev,
      { id: Date.now().toString(), role: 'user', content: question, timestamp: new Date().toISOString() },
    ])

    try {
      const res = await fetch(`/api/copilot/chat?host=${hostMode}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: question }),
      })
      if (res.ok) {
        const json = await res.json()
        setChatMessages(json.history || [])
      }
    } catch (e) {
      console.error('Copilot request failed:', e)
    } finally {
      setChatLoading(false)
    }
  }

  const handleExportReport = () => {
    if (!data) return
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `aiva-ks-incident-report-${data.host_id}-${Date.now()}.json`
    a.click()
  }

  const filteredTimeline = useMemo(() => {
    if (!data) return []
    return data.timeline_events.filter((evt) => {
      const matchText =
        !timelineFilter ||
        evt.event_type.toLowerCase().includes(timelineFilter.toLowerCase()) ||
        evt.comm.toLowerCase().includes(timelineFilter.toLowerCase()) ||
        String(evt.pid).includes(timelineFilter)
      const matchRisk = evt.anomaly_score >= minRiskFilter
      return matchText && matchRisk
    })
  }, [data, timelineFilter, minRiskFilter])

  if (loading && !data) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-[#080c14] text-cyan-400 font-mono">
        <div className="flex flex-col items-center gap-4">
          <Activity className="h-8 w-8 animate-spin text-cyan-500" />
          <p className="text-xs uppercase tracking-widest text-slate-400">CONNECTING TO eBPF KERNEL SENSORS...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-[#080c14] text-slate-200 flex flex-col font-sans select-none">
      {/* Top SOC Command Header */}
      <header className="border-b border-slate-800 bg-[#0d131f]/95 backdrop-blur px-5 py-2.5 flex flex-wrap items-center justify-between gap-3 sticky top-0 z-50">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center p-1.5 rounded-lg bg-red-950/50 border border-red-600/60 shadow-md shadow-red-950/50">
            <ShieldAlert className="h-5 w-5 text-red-400" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-sm font-black tracking-tight text-white font-mono">AIVA-KS</span>
              <span className="text-[10px] px-1.5 py-0.5 rounded font-mono bg-cyan-950/80 border border-cyan-800 text-cyan-400 font-bold">
                eBPF SOC SENTRY
              </span>
              <span className="text-[10px] px-1.5 py-0.5 rounded font-mono bg-emerald-950/80 border border-emerald-800 text-emerald-400 font-bold flex items-center gap-1">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                ACTIVE
              </span>
            </div>
            <p className="text-[11px] text-slate-400 font-mono">
              Target: <span className="text-cyan-300 font-semibold">{data?.host_id}</span> ({hostMode === 'live' ? 'Live System OS' : 'Simulated Attack Host'})
            </p>
          </div>
        </div>

        {/* HOST ENVIRONMENT DUAL SWITCH (Live OS vs Test OS) */}
        <div className="flex items-center bg-slate-950 border border-slate-800 p-1 rounded-xl shadow-inner">
          <button
            onClick={() => {
              setHostMode('live')
              setSelectedNode(null)
            }}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition-all cursor-pointer ${
              hostMode === 'live'
                ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/50 shadow-sm shadow-emerald-950'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/50'
            }`}
          >
            <span className={`h-2 w-2 rounded-full ${hostMode === 'live' ? 'bg-emerald-400 animate-pulse' : 'bg-slate-600'}`} />
            Live OS Host
          </button>

          <button
            onClick={() => {
              setHostMode('test')
              setSelectedNode(null)
            }}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition-all cursor-pointer ${
              hostMode === 'test'
                ? 'bg-red-500/20 text-red-300 border border-red-500/50 shadow-sm shadow-red-950'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/50'
            }`}
          >
            <span className={`h-2 w-2 rounded-full ${hostMode === 'test' ? 'bg-red-400 animate-pulse' : 'bg-slate-600'}`} />
            Test Attack Host
          </button>
        </div>

        {/* Global Security Metrics Banner */}
        <div className="hidden xl:flex items-center gap-6">
          <div className="flex items-center gap-3 bg-slate-900/90 border border-slate-800 px-3 py-1.5 rounded-lg">
            <div className="flex flex-col">
              <span className="text-[9px] uppercase font-mono text-slate-400 tracking-wider">Causal Blast Risk</span>
              <div className="flex items-center gap-2">
                <span
                  className={`text-sm font-black font-mono ${
                    (data?.overall_risk ?? 0) > 0.7 ? 'text-red-400' : (data?.overall_risk ?? 0) > 0.4 ? 'text-amber-400' : 'text-emerald-400'
                  }`}
                >
                  {((data?.overall_risk ?? 0) * 100).toFixed(0)}%
                </span>
                <div className="w-20 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full ${
                      (data?.overall_risk ?? 0) > 0.7 ? 'bg-red-500' : (data?.overall_risk ?? 0) > 0.4 ? 'bg-amber-500' : 'bg-emerald-500'
                    }`}
                    style={{ width: `${(data?.overall_risk ?? 0) * 100}%` }}
                  />
                </div>
              </div>
            </div>
          </div>

          {/* Subsystem Heatmap Quick Badges */}
          <div className="flex items-center gap-1.5">
            {data?.threat_heatmap &&
              Object.entries(data.threat_heatmap).map(([area, val]) => {
                const score = typeof val === 'number' ? val : (val?.score ?? 0)
                return (
                  <div
                    key={area}
                    className="px-2 py-1 rounded bg-slate-900 border border-slate-800 flex flex-col items-center min-w-[58px]"
                  >
                    <span className="text-[8px] uppercase font-mono text-slate-400">{area.slice(0, 4)}</span>
                    <span
                      className={`text-[11px] font-mono font-bold ${
                        score >= 0.7 ? 'text-red-400' : score >= 0.3 ? 'text-amber-400' : 'text-emerald-400'
                      }`}
                    >
                      {(score * 100).toFixed(0)}%
                    </span>
                  </div>
                )
              })}
          </div>
        </div>

        {/* Analyst Actions */}
        <div className="flex items-center gap-2">
          <button
            onClick={handleInjectTelemetry}
            disabled={simulating}
            className="flex items-center gap-1 px-2.5 py-1.5 text-xs font-semibold rounded bg-amber-500/10 border border-amber-500/40 text-amber-300 hover:bg-amber-500/20 transition cursor-pointer"
            title="Inject real-time telemetry event into eBPF pipeline"
          >
            <Zap className="h-3.5 w-3.5" />
            {simulating ? 'Ingesting...' : 'Inject Attack'}
          </button>

          <button
            onClick={handleExportReport}
            className="flex items-center gap-1 px-2.5 py-1.5 text-xs font-semibold rounded bg-slate-800 border border-slate-700 text-slate-300 hover:bg-slate-700 transition cursor-pointer"
            title="Download Incident JSON Report"
          >
            <Download className="h-3.5 w-3.5" />
            Export JSON
          </button>

          <button
            onClick={fetchDashboard}
            className="p-1.5 rounded bg-slate-800 border border-slate-700 text-slate-300 hover:bg-slate-700 transition cursor-pointer"
            title="Refresh State"
          >
            <RefreshCw className="h-3.5 w-3.5" />
          </button>
        </div>
      </header>

      {/* Navigation & Section Tabs */}
      <div className="bg-[#0b101b] border-b border-slate-800/80 px-4 flex items-center justify-between">
        <div className="flex gap-1 overflow-x-auto">
          {[
            { id: 'workbench', label: 'SOC Investigation Workbench', icon: Layers, count: data?.stats.node_count },
            { id: 'mitre', label: 'MITRE ATT&CK Matrix', icon: ShieldAlert, count: data?.stats.mitre_count },
            { id: 'forensics', label: 'Kernel Syscall Forensics', icon: Terminal, count: data?.stats.total_events },
            { id: 'response', label: 'Policy Containment Engine', icon: Lock, count: data?.stats.pending_approvals },
            { id: 'copilot', label: 'SOC Copilot (RAG)', icon: Sparkles, count: undefined },
          ].map((tab) => {
            const Icon = tab.icon
            const active = activeTab === tab.id
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={`flex items-center gap-2 px-3 py-2.5 text-xs font-medium border-b-2 transition cursor-pointer whitespace-nowrap ${
                  active
                    ? 'border-cyan-400 text-cyan-300 bg-slate-900/60'
                    : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900/30'
                }`}
              >
                <Icon className={`h-4 w-4 ${active ? 'text-cyan-400' : 'text-slate-500'}`} />
                <span>{tab.label}</span>
                {tab.count !== undefined && (
                  <span
                    className={`text-[10px] px-1.5 py-0.2 rounded font-mono ${
                      active ? 'bg-cyan-950 text-cyan-300 border border-cyan-800' : 'bg-slate-800 text-slate-400'
                    }`}
                  >
                    {tab.count}
                  </span>
                )}
              </button>
            )
          })}
        </div>

        <div className="hidden sm:flex items-center gap-2 text-xs font-mono text-slate-400">
          <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
          <span>Zero-Disruption Safe Mode: ACTIVE</span>
        </div>
      </div>

      {/* Main Multi-Pane Analyst Workspace */}
      <main className="flex-1 flex flex-col overflow-hidden">
        {/* VIEW 1: SOC INVESTIGATION WORKBENCH (Graph + Explainability + Blast Radius) */}
        {activeTab === 'workbench' && (
          <div className="flex-1 grid grid-cols-1 lg:grid-cols-12 overflow-hidden">
            {/* Left Graph Panel (7 Cols) */}
            <div className="lg:col-span-8 flex flex-col border-r border-slate-800 bg-[#080c14] relative">
              {/* Canvas Controls Bar */}
              <div className="absolute top-3 left-3 z-10 flex items-center gap-2 bg-slate-900/90 backdrop-blur border border-slate-800 px-3 py-1.5 rounded-lg shadow-lg">
                <span className="text-xs font-mono font-semibold text-slate-300 flex items-center gap-1.5">
                  <Activity className="h-3.5 w-3.5 text-cyan-400" />
                  Causal Attack Graph
                </span>
                <span className="text-slate-600">|</span>
                <span className="text-[11px] font-mono text-slate-400">
                  {nodes.length} Nodes · {edges.length} Edges
                </span>
              </div>

              {/* Interactive ReactFlow Graph Canvas */}
              <div className="flex-1 w-full h-[540px] lg:h-full">
                <ReactFlow
                  nodes={nodes}
                  edges={edges}
                  onNodesChange={onNodesChange}
                  onEdgesChange={onEdgesChange}
                  onNodeClick={onNodeClick}
                  nodeTypes={nodeTypes}
                  fitView
                  attributionPosition="bottom-left"
                >
                  <Background color="#1e293b" gap={20} size={1} />
                  <Controls className="!m-3" />
                  <MiniMap
                    nodeStrokeWidth={3}
                    nodeColor={(n: any) => (n.data?.risk > 0.6 ? '#f43f5e' : '#06b6d4')}
                    maskColor="#080c14c0"
                    className="!m-3 !border-slate-800 !bg-slate-950 !rounded-lg"
                  />
                </ReactFlow>
              </div>

              {/* Bottom Grounded XAI Narrative Bar */}
              <div className="border-t border-slate-800 bg-slate-950/90 p-3.5">
                <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 mb-1">
                  <FileText className="h-3.5 w-3.5" />
                  <span>XAI Grounded Attack Narrative (Deterministic Evidence Extraction)</span>
                </div>
                <p className="text-xs font-mono text-slate-300 leading-relaxed bg-slate-900/60 p-2.5 rounded border border-slate-800/80">
                  {data?.narrative}
                </p>
              </div>
            </div>

            {/* Right Entity Inspector & Mitigation Panel (4 Cols) */}
            <div className="lg:col-span-4 flex flex-col bg-[#0b0f17] overflow-y-auto p-4 gap-4">
              {/* Selected Entity Deep-Dive */}
              <div className="rounded-xl bg-slate-900/80 border border-slate-800 p-4">
                <div className="flex items-center justify-between mb-3 border-b border-slate-800/80 pb-2">
                  <span className="text-xs font-mono uppercase text-slate-400 flex items-center gap-1.5">
                    <Eye className="h-4 w-4 text-cyan-400" />
                    Entity Forensic Inspector
                  </span>
                  {selectedNode && (
                    <span
                      className={`text-xs font-mono font-bold px-2 py-0.5 rounded ${
                        selectedNode.risk >= 0.7
                          ? 'bg-red-950 text-red-400 border border-red-800'
                          : selectedNode.risk >= 0.3
                          ? 'bg-amber-950 text-amber-400 border border-amber-800'
                          : 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                      }`}
                    >
                      Blast Risk: {(selectedNode.risk * 100).toFixed(0)}%
                    </span>
                  )}
                </div>

                {selectedNode ? (
                  <div className="space-y-3 text-xs font-mono">
                    <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                      <span className="text-[10px] text-slate-500 uppercase">Entity Identifier</span>
                      <p className="text-sm font-bold text-white mt-0.5 break-all">{selectedNode.label}</p>
                      <div className="flex gap-2 mt-2">
                        <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px]">
                          Type: {selectedNode.type}
                        </span>
                        <span className="px-1.5 py-0.5 rounded bg-slate-800 text-cyan-300 text-[10px]">
                          ID: {selectedNode.id}
                        </span>
                      </div>
                    </div>

                    {/* Causal Edges */}
                    <div>
                      <span className="text-[11px] text-slate-400 block mb-1">Causal Relationships</span>
                      <div className="space-y-1.5 max-h-36 overflow-y-auto">
                        {data?.graph.edges
                          .filter((e) => e.source === selectedNode.id || e.target === selectedNode.id)
                          .map((e) => (
                            <div key={e.id} className="p-2 rounded bg-slate-950 border border-slate-800/80 text-[11px]">
                              <span className="text-cyan-400">{e.source}</span>
                              <span className="text-slate-500 mx-1">──[{e.relation}]──►</span>
                              <span className="text-amber-400">{e.target}</span>
                            </div>
                          ))}
                      </div>
                    </div>

                    {/* Telemetry Attributes */}
                    <div>
                      <span className="text-[11px] text-slate-400 block mb-1">Raw Telemetry Attributes</span>
                      <pre className="p-2.5 rounded bg-slate-950 border border-slate-800/80 text-[11px] text-slate-300 overflow-x-auto max-h-36">
                        {JSON.stringify(selectedNode.metadata, null, 2)}
                      </pre>
                    </div>
                  </div>
                ) : (
                  <p className="text-xs text-slate-500 font-mono">Select a node in the attack graph to inspect.</p>
                )}
              </div>

              {/* Pending Mitigation Approvals */}
              <div className="rounded-xl bg-slate-900/80 border border-slate-800 p-4">
                <div className="flex items-center justify-between mb-3 border-b border-slate-800/80 pb-2">
                  <span className="text-xs font-mono uppercase text-slate-400 flex items-center gap-1.5">
                    <Lock className="h-4 w-4 text-amber-400" />
                    Pending Human-in-the-Loop Actions
                  </span>
                  <span className="text-[10px] font-mono text-amber-400 px-1.5 py-0.5 rounded bg-amber-950 border border-amber-800">
                    {data?.stats.pending_approvals} Pending
                  </span>
                </div>

                <div className="space-y-2.5">
                  {data?.response_actions
                    .filter((a) => a.status === 'pending_approval')
                    .map((act) => (
                      <div key={act.action_id} className="p-3 rounded-lg bg-slate-950 border border-amber-900/60 text-xs">
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-white font-mono">{act.action_type}</span>
                          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-amber-950 text-amber-400 border border-amber-800">
                            Awaiting Approval
                          </span>
                        </div>
                        <p className="text-slate-400 text-[11px] mt-1 font-mono">Policy: {act.policy_name}</p>
                        <p className="text-slate-500 text-[10px] font-mono mt-0.5">Target: {JSON.stringify(act.target)}</p>

                        <div className="flex gap-2 mt-3 pt-2 border-t border-slate-800">
                          <button
                            onClick={() => handleApproveAction(act.action_id, true)}
                            className="flex-1 py-1 bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-[11px] rounded transition cursor-pointer flex items-center justify-center gap-1"
                          >
                            <Check className="h-3 w-3" /> Approve
                          </button>
                          <button
                            onClick={() => handleApproveAction(act.action_id, false)}
                            className="flex-1 py-1 bg-slate-800 hover:bg-red-950 text-slate-300 hover:text-red-400 border border-slate-700 text-[11px] rounded transition cursor-pointer flex items-center justify-center gap-1"
                          >
                            <XCircle className="h-3 w-3" /> Reject
                          </button>
                        </div>
                      </div>
                    ))}
                  {data?.stats.pending_approvals === 0 && (
                    <p className="text-xs text-slate-500 font-mono">All evaluated policy actions are nominal.</p>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* VIEW 2: MITRE ATT&CK MATRIX */}
        {activeTab === 'mitre' && (
          <div className="flex-1 p-6 overflow-y-auto">
            <div className="mb-4">
              <h2 className="text-sm font-bold text-white uppercase tracking-wider font-mono flex items-center gap-2">
                <ShieldAlert className="h-4 w-4 text-cyan-400" />
                MITRE ATT&CK Behavioral Kill-Chain Alignments
              </h2>
              <p className="text-xs text-slate-400">
                Rule & graph-grounded mapping of low-level kernel syscall evidence to ATT&CK Enterprise Matrix.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {data?.mitre_matches.map((m) => (
                <div
                  key={m.technique_id}
                  className="rounded-xl bg-slate-900/80 border border-slate-800 p-4 flex flex-col justify-between"
                >
                  <div>
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <div className="flex items-center gap-1.5">
                          <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-red-950 border border-red-800 text-red-400">
                            {m.technique_id}
                          </span>
                          <span className="text-[11px] font-mono text-cyan-400">{m.tactic}</span>
                        </div>
                        <h3 className="text-sm font-bold text-white mt-1.5 font-mono">{m.name}</h3>
                      </div>
                      <span className="text-xs font-mono font-bold text-amber-400 bg-amber-950/50 border border-amber-800 px-2 py-0.5 rounded">
                        {m.confidence}% Conf
                      </span>
                    </div>

                    <p className="text-xs text-slate-300 mt-2.5 leading-relaxed font-mono">{m.description}</p>
                  </div>

                  <div className="mt-4 pt-3 border-t border-slate-800">
                    <span className="text-[11px] font-mono text-slate-400 block mb-1">Evidence Citations:</span>
                    <div className="space-y-1">
                      {m.evidence.map((ev, i) => (
                        <div key={i} className="text-[11px] font-mono text-slate-300 bg-slate-950 p-1.5 rounded border border-slate-800/80">
                          • {ev}
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* VIEW 3: KERNEL SYSCALL FORENSICS (Searchable Event Stream) */}
        {activeTab === 'forensics' && (
          <div className="flex-1 p-6 overflow-y-auto flex flex-col gap-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-slate-900/80 p-4 rounded-xl border border-slate-800">
              <div>
                <h2 className="text-sm font-bold text-white uppercase tracking-wider font-mono flex items-center gap-2">
                  <Terminal className="h-4 w-4 text-cyan-400" />
                  Kernel Syscall Forensic Stream
                </h2>
                <p className="text-xs text-slate-400">
                  Filter, search, and audit raw eBPF sensor telemetry (`execve`, `mprotect`, `ptrace`, `connect`).
                </p>
              </div>

              <div className="flex items-center gap-3">
                <div className="relative">
                  <Search className="h-3.5 w-3.5 absolute left-2.5 top-2.5 text-slate-500" />
                  <input
                    type="text"
                    placeholder="Search PID, Comm, Syscall..."
                    value={timelineFilter}
                    onChange={(e) => setTimelineFilter(e.target.value)}
                    className="pl-8 pr-3 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                  />
                </div>
                <select
                  value={minRiskFilter}
                  onChange={(e) => setMinRiskFilter(Number(e.target.value))}
                  className="px-2.5 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-200 font-mono"
                >
                  <option value={0}>All Anomaly Scores</option>
                  <option value={0.5}>Score ≥ 0.5 (Suspicious)</option>
                  <option value={0.8}>Score ≥ 0.8 (Critical)</option>
                </select>
              </div>
            </div>

            {/* Table of Events */}
            <div className="rounded-xl border border-slate-800 overflow-hidden bg-slate-900/40">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-slate-950 border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                  <tr>
                    <th className="p-3">Timestamp</th>
                    <th className="p-3">Syscall Event</th>
                    <th className="p-3">Process (PID)</th>
                    <th className="p-3">Anomaly Score</th>
                    <th className="p-3">Parameters / Features</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {filteredTimeline.map((evt, idx) => {
                    const isHigh = evt.anomaly_score >= 0.7
                    return (
                      <tr key={idx} className={isHigh ? 'bg-red-950/20' : 'hover:bg-slate-900/50'}>
                        <td className="p-3 text-slate-400 whitespace-nowrap">{evt.timestamp}</td>
                        <td className="p-3 font-bold text-white">{evt.event_type}</td>
                        <td className="p-3 text-cyan-300">
                          {evt.comm} <span className="text-slate-500">({evt.pid})</span>
                        </td>
                        <td className="p-3">
                          <span
                            className={`px-2 py-0.5 rounded font-bold ${
                              isHigh
                                ? 'bg-red-950 text-red-400 border border-red-800'
                                : evt.anomaly_score >= 0.3
                                ? 'bg-amber-950 text-amber-400 border border-amber-800'
                                : 'bg-slate-800 text-slate-400'
                            }`}
                          >
                            {(evt.anomaly_score * 100).toFixed(0)}%
                          </span>
                        </td>
                        <td className="p-3 text-slate-300">
                          <div className="flex flex-wrap gap-1.5">
                            {Object.entries(evt.details).map(([k, v]) => (
                              <span key={k} className="px-1.5 py-0.2 rounded bg-slate-950 border border-slate-800 text-[10px]">
                                <span className="text-slate-500">{k}:</span> {String(v)}
                              </span>
                            ))}
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* VIEW 4: POLICY ENGINE & AUDIT TRAIL */}
        {activeTab === 'response' && (
          <div className="flex-1 p-6 overflow-y-auto flex flex-col gap-6">
            <div>
              <h2 className="text-sm font-bold text-white uppercase tracking-wider font-mono flex items-center gap-2">
                <Lock className="h-4 w-4 text-cyan-400" />
                Zero-Disruption Containment Policy Decisions
              </h2>
              <p className="text-xs text-slate-400">
                Audited action proposals evaluated against kernel safety policies and blast radiuses.
              </p>
            </div>

            {/* Action Cards */}
            <div className="space-y-3">
              {data?.response_actions.map((act) => (
                <div
                  key={act.action_id}
                  className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-4 font-mono"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-bold px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-cyan-400">
                        {act.action_id}
                      </span>
                      <span className="text-sm font-bold text-white">{act.action_type}</span>
                      <span
                        className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase ${
                          act.status === 'pending_approval'
                            ? 'bg-amber-950 text-amber-400 border border-amber-800'
                            : act.status === 'executed'
                            ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                            : 'bg-slate-800 text-slate-400'
                        }`}
                      >
                        {act.status}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400">
                      Policy Rule: <span className="text-slate-200">{act.policy_name}</span>
                    </p>
                    <p className="text-[11px] text-slate-500">Target Spec: {JSON.stringify(act.target)}</p>
                  </div>

                  {act.status === 'pending_approval' && (
                    <div className="flex gap-2">
                      <button
                        onClick={() => handleApproveAction(act.action_id, true)}
                        className="px-3.5 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs rounded transition cursor-pointer flex items-center gap-1.5"
                      >
                        <CheckCircle2 className="h-3.5 w-3.5" /> Approve & Enforce
                      </button>
                      <button
                        onClick={() => handleApproveAction(act.action_id, false)}
                        className="px-3.5 py-1.5 bg-slate-800 hover:bg-red-950 text-slate-300 hover:text-red-400 border border-slate-700 text-xs rounded transition cursor-pointer flex items-center gap-1.5"
                      >
                        <XCircle className="h-3.5 w-3.5" /> Reject
                      </button>
                    </div>
                  )}
                </div>
              ))}
            </div>

            {/* Audit Log */}
            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
              <h3 className="text-xs font-mono uppercase text-slate-300 mb-3">Immutable Analyst Audit Ledger</h3>
              <div className="space-y-2">
                {data?.audit_log && data.audit_log.length > 0 ? (
                  data.audit_log.map((log) => (
                    <div key={log.id} className="p-2.5 rounded bg-slate-950 border border-slate-800/80 text-xs font-mono flex items-center justify-between">
                      <div>
                        <span className="text-cyan-400">[{log.timestamp}]</span> <span className="text-white font-bold">{log.actor}</span>: {log.details}
                      </div>
                      <span className="text-[10px] px-2 py-0.5 rounded font-bold bg-emerald-950 text-emerald-400 border border-emerald-800">
                        {log.status}
                      </span>
                    </div>
                  ))
                ) : (
                  <p className="text-xs text-slate-500 font-mono">Ledger nominal. Decisions recorded here when approved.</p>
                )}
              </div>
            </div>
          </div>
        )}

        {/* VIEW 5: SOC COPILOT (RAG Assistant) */}
        {activeTab === 'copilot' && (
          <div className="flex-1 p-6 overflow-hidden flex flex-col gap-4">
            <div>
              <h2 className="text-sm font-bold text-white uppercase tracking-wider font-mono flex items-center gap-2">
                <Sparkles className="h-4 w-4 text-cyan-400" />
                Security Copilot (Context-Grounded RAG Assistant)
              </h2>
              <p className="text-xs text-slate-400">
                Ask questions about causal chains, injection signatures, blast radius, or response actions.
              </p>
            </div>

            <div className="flex-1 flex flex-col bg-slate-900/60 border border-slate-800 rounded-xl p-4 overflow-hidden">
              <div className="flex-1 overflow-y-auto space-y-3.5 pr-2">
                {chatMessages.map((msg) => (
                  <div key={msg.id} className={`flex gap-3 ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                    {msg.role === 'assistant' && (
                      <div className="h-7 w-7 rounded-lg bg-cyan-950 border border-cyan-800 flex items-center justify-center text-cyan-400 shrink-0">
                        <Sparkles className="h-3.5 w-3.5" />
                      </div>
                    )}
                    <div
                      className={`p-3.5 rounded-xl max-w-2xl text-xs leading-relaxed font-mono ${
                        msg.role === 'user'
                          ? 'bg-cyan-700 text-white'
                          : 'bg-slate-950 border border-slate-800 text-slate-200 whitespace-pre-wrap'
                      }`}
                    >
                      {msg.content}
                      <div className="text-[9px] opacity-50 mt-1 font-mono">{msg.timestamp}</div>
                    </div>
                  </div>
                ))}
                {chatLoading && (
                  <div className="flex items-center gap-2 text-xs text-cyan-400 font-mono">
                    <Activity className="h-3.5 w-3.5 animate-spin" />
                    Querying kernel graph evidence and telemetry context...
                  </div>
                )}
              </div>

              <form onSubmit={handleSendChat} className="mt-4 pt-3 border-t border-slate-800 flex gap-2">
                <input
                  type="text"
                  placeholder="Ask Copilot: 'What happened?', 'Explain memory injection evidence', or 'Summarize response options'..."
                  value={chatInput}
                  onChange={(e) => setChatInput(e.target.value)}
                  className="flex-1 px-3.5 py-2 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                />
                <button
                  type="submit"
                  disabled={chatLoading || !chatInput.trim()}
                  className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-bold text-xs rounded-lg flex items-center gap-1.5 transition cursor-pointer font-mono"
                >
                  <Send className="h-3.5 w-3.5" /> Send
                </button>
              </form>
            </div>
          </div>
        )}
      </main>
    </div>
  )
}


