import { useState, useEffect, useMemo, useCallback } from 'react'

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
  Home,
  Search,
  Calendar,
  Share2,
  Target,
  BrainCircuit,
  Shield,
  Folder,
  Settings as SettingsIcon,
  Zap,
  Download,
  RefreshCw,
  Cpu,
  Globe,
  FileCode,
  HardDrive,
  Radio,
  Lock,
  Eye,
  Sparkles,
  Activity,
  ShieldAlert,
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

interface DashboardData {
  host_id: string
  host_mode: string
  live_host_id: string
  test_host_id: string
  overall_risk: number
  threat_heatmap: Record<string, any>
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

// --- Custom ReactFlow Node for Enterprise SOC ---
const SOCNodeComponent = ({ data }: { data: GraphNodeData }) => {
  const isHigh = data.risk >= 0.7
  const isMed = data.risk >= 0.3 && data.risk < 0.7

  const getIcon = () => {
    switch (data.nodeType?.toLowerCase()) {
      case 'process':
        return <Cpu className="h-3.5 w-3.5 text-indigo-400" />
      case 'socket':
        return <Globe className="h-3.5 w-3.5 text-cyan-400" />
      case 'file':
        return <FileCode className="h-3.5 w-3.5 text-emerald-400" />
      case 'memory':
      case 'memoryregion':
        return <HardDrive className="h-3.5 w-3.5 text-amber-400" />
      default:
        return <Radio className="h-3.5 w-3.5 text-slate-400" />
    }
  }

  return (
    <div
      className={`px-3 py-2 rounded-lg border shadow-lg backdrop-blur-md min-w-[160px] transition-all cursor-pointer font-sans ${
        data.isSelected
          ? 'bg-[#182030] border-cyan-400 ring-2 ring-cyan-500/40 shadow-cyan-950/50 scale-105'
          : isHigh
          ? 'bg-[#1d1418] border-red-500/60 hover:border-red-400 shadow-red-950/30'
          : isMed
          ? 'bg-[#1d1912] border-amber-500/60 hover:border-amber-400 shadow-amber-950/30'
          : 'bg-[#121722] border-slate-700/70 hover:border-slate-500'
      }`}
    >
      <Handle type="target" position={Position.Top} className="!bg-cyan-400 !w-2 !h-2 !border-2 !border-[#0b0e14]" />
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-1.5 min-w-0">
          <div className="p-1 rounded bg-[#0b0e14] border border-slate-800">{getIcon()}</div>
          <span className="text-[10px] font-mono font-semibold uppercase tracking-wider text-slate-300 truncate">
            {data.nodeType}
          </span>
        </div>
        <span
          className={`text-[10px] font-mono font-bold px-1.5 py-0.2 rounded ${
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
      <div className="text-xs font-semibold font-mono text-slate-100 mt-1.5 truncate max-w-[150px]" title={data.label}>
        {data.label}
      </div>
      <Handle type="source" position={Position.Bottom} className="!bg-cyan-400 !w-2 !h-2 !border-2 !border-[#0b0e14]" />
    </div>
  )
}

const nodeTypes = { socNode: SOCNodeComponent }

export default function App() {
  const [activeTab, setActiveTab] = useState<
    'overview' | 'investigations' | 'timeline' | 'graph' | 'mitre' | 'ai_analyst' | 'response_center' | 'cases' | 'settings'
  >('overview')

  const [hostMode, setHostMode] = useState<'live' | 'test'>('live')
  const [data, setData] = useState<DashboardData | null>(null)
  const [casesList, setCasesList] = useState<any[]>([])
  const [threatIntelFeed, setThreatIntelFeed] = useState<any[]>([])
  const [selectedNode, setSelectedNode] = useState<any | null>(null)
  const [loading, setLoading] = useState(true)
  const [simulating, setSimulating] = useState(false)
  const [timelineFilter, setTimelineFilter] = useState('')
  const [minRiskFilter, setMinRiskFilter] = useState(0)

  // ReactFlow Canvas State
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([])
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([])

  // Security Copilot Chat State
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([])
  const [chatInput, setChatInput] = useState('')
  const [chatLoading, setChatLoading] = useState(false)

  const fetchDashboard = useCallback(async () => {
    try {
      const res = await fetch(`/api/dashboard/summary?host=${hostMode}`)
      if (res.ok) {
        const json: DashboardData = await res.json()
        setData(json)

        const rfNodes: Node[] = json.graph.nodes.map((node, index) => {
          const col = index % 3
          const row = Math.floor(index / 3)
          return {
            id: node.id,
            type: 'socNode',
            position: { x: 40 + col * 250, y: 40 + row * 120 },
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
          labelStyle: { fill: '#cbd5e1', fontSize: 10, fontFamily: 'JetBrains Mono', fontWeight: 600 },
          labelBgStyle: { fill: '#0b0e14', fillOpacity: 0.95 },
          labelBgPadding: [5, 2],
          labelBgBorderRadius: 4,
          animated: edge.weight > 0.5,
          markerEnd: { type: MarkerType.ArrowClosed, color: edge.weight > 0.5 ? '#f43f5e' : '#38bdf8', width: 12, height: 12 },
          style: { stroke: edge.weight > 0.5 ? '#f43f5e' : '#0284c7', strokeWidth: edge.weight > 0.5 ? 2 : 1.5 },
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
      console.error('Error fetching dashboard summary:', e)
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

  const fetchCasesAndIntel = useCallback(async () => {
    try {
      const resCases = await fetch('/api/cases')
      if (resCases.ok) {
        const json = await resCases.json()
        setCasesList(json.cases || [])
      }
      const resIntel = await fetch('/api/threat_intel/feed')
      if (resIntel.ok) {
        const json = await resIntel.json()
        setThreatIntelFeed(json.indicators || [])
      }
    } catch (e) {
      console.error('Error fetching cases or threat intel:', e)
    }
  }, [])

  useEffect(() => {
    fetchDashboard()
    fetchChatHistory()
    fetchCasesAndIntel()
    const interval = setInterval(fetchDashboard, 1000)
    return () => clearInterval(interval)
  }, [fetchDashboard, fetchChatHistory, fetchCasesAndIntel])

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
        body: JSON.stringify({ action_id: actionId, approver: 'Lead_SOC_Analyst', approved }),
      })
      await fetchDashboard()
    } catch (e) {
      console.error('Failed to submit approval:', e)
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

  const handleSendChat = async (promptText?: string) => {
    const textToSend = promptText || chatInput
    if (!textToSend.trim() || chatLoading) return

    setChatInput('')
    setChatLoading(true)

    setChatMessages((prev) => [
      ...prev,
      { id: Date.now().toString(), role: 'user', content: textToSend, timestamp: new Date().toISOString() },
    ])

    try {
      const res = await fetch(`/api/copilot/chat?host=${hostMode}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: textToSend }),
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
    a.download = `CHRONOS-Incident-Report-${data.host_id}-${Date.now()}.json`
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
      <div className="flex min-h-screen items-center justify-center bg-[#0b0e14] text-slate-300 font-sans">
        <div className="flex flex-col items-center gap-3">
          <Activity className="h-7 w-7 animate-spin text-cyan-400" />
          <span className="text-xs font-mono uppercase tracking-widest text-slate-400">INITIALIZING CHRONOS OPERATING SYSTEM...</span>
        </div>
      </div>
    )
  }

  return (
    <div className="flex h-screen bg-[#0b0e14] text-slate-200 font-sans antialiased overflow-hidden select-none">
      {/* GLOBAL NAVIGATION (LEFT SIDEBAR) */}
      <aside className="w-64 bg-[#121620] border-r border-[#1e2638] flex flex-col shrink-0 z-20">
        {/* Brand Logo & Version */}
        <div className="p-4 border-b border-[#1e2638] flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="h-7 w-7 rounded-lg bg-indigo-600/20 border border-indigo-500/40 flex items-center justify-center text-indigo-400">
              <Shield className="h-4 w-4" />
            </div>
            <div>
              <span className="text-sm font-bold tracking-tight text-white font-sans">CHRONOS</span>
              <span className="text-[10px] font-mono text-cyan-400 ml-1.5 px-1 py-0.2 rounded bg-cyan-950 border border-cyan-800">
                v2.0
              </span>
            </div>
          </div>
        </div>

        {/* Host Environment Switcher */}
        <div className="p-3 border-b border-[#1e2638]">
          <div className="bg-[#0b0e14] p-1 rounded-lg border border-[#1e2638] flex">
            <button
              onClick={() => {
                setHostMode('live')
                setSelectedNode(null)
              }}
              className={`flex-1 flex items-center justify-center gap-1.5 py-1 text-[11px] font-mono font-medium rounded transition cursor-pointer ${
                hostMode === 'live' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <span className={`h-1.5 w-1.5 rounded-full ${hostMode === 'live' ? 'bg-emerald-400 animate-pulse' : 'bg-slate-600'}`} />
              Live Host
            </button>

            <button
              onClick={() => {
                setHostMode('test')
                setSelectedNode(null)
              }}
              className={`flex-1 flex items-center justify-center gap-1.5 py-1 text-[11px] font-mono font-medium rounded transition cursor-pointer ${
                hostMode === 'test' ? 'bg-red-500/20 text-red-300 border border-red-500/40' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <span className={`h-1.5 w-1.5 rounded-full ${hostMode === 'test' ? 'bg-red-400 animate-pulse' : 'bg-slate-600'}`} />
              Test Host
            </button>
          </div>
        </div>

        {/* Navigation Items */}
        <nav className="flex-1 p-3 space-y-1 overflow-y-auto font-sans">
          {[
            { id: 'overview', label: 'Overview', icon: Home },
            { id: 'investigations', label: 'Investigations', icon: Search, badge: data?.stats.node_count },
            { id: 'timeline', label: 'Attack Timeline', icon: Calendar, badge: data?.stats.total_events },
            { id: 'graph', label: 'Attack Graph', icon: Share2 },
            { id: 'mitre', label: 'MITRE ATT&CK', icon: Target, badge: data?.stats.mitre_count },
            { id: 'ai_analyst', label: 'AI Analyst', icon: BrainCircuit },
            { id: 'response_center', label: 'Response Center', icon: ShieldAlert, badge: data?.stats.pending_approvals },
            { id: 'cases', label: 'Cases', icon: Folder, badge: casesList.length },
            { id: 'settings', label: 'Settings', icon: SettingsIcon },
          ].map((item) => {
            const Icon = item.icon
            const isActive = activeTab === item.id
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id as any)}
                className={`w-full flex items-center justify-between px-3 py-2 rounded-md text-xs font-medium transition cursor-pointer ${
                  isActive
                    ? 'bg-indigo-600/15 text-indigo-300 border-l-2 border-indigo-400 font-semibold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-[#182030]'
                }`}
              >
                <div className="flex items-center gap-2.5">
                  <Icon className={`h-4 w-4 ${isActive ? 'text-indigo-400' : 'text-slate-500'}`} />
                  <span>{item.label}</span>
                </div>
                {item.badge !== undefined && (
                  <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded ${isActive ? 'bg-indigo-950 text-indigo-300' : 'bg-[#1a2232] text-slate-400'}`}>
                    {item.badge}
                  </span>
                )}
              </button>
            )
          })}
        </nav>

        {/* User Identity Footer */}
        <div className="p-3 border-t border-[#1e2638] flex items-center gap-2.5 text-xs">
          <div className="h-7 w-7 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center font-mono font-bold text-slate-300">
            SA
          </div>
          <div className="flex flex-col truncate">
            <span className="font-semibold text-slate-200 truncate">Lead SOC Analyst</span>
            <span className="text-[10px] font-mono text-slate-400 truncate">{data?.host_id}</span>
          </div>
        </div>
      </aside>

      {/* MAIN CONTENT WORKSPACE */}
      <div className="flex-1 flex flex-col overflow-hidden bg-[#0b0e14]">
        {/* TOP HEADER ASSESSMENT BAR (First 5 Seconds Focus) */}
        <header className="bg-[#121620] border-b border-[#1e2638] px-6 py-3 flex items-center justify-between gap-4">
          {/* Top Assessment Highlights */}
          <div className="flex items-center gap-6">
            <div className="flex items-center gap-2">
              <span className="text-xs uppercase font-mono font-bold text-slate-400">Target Host:</span>
              <span className="text-xs font-mono font-bold text-cyan-300 bg-cyan-950/60 border border-cyan-800/80 px-2 py-0.5 rounded">
                {data?.host_id}
              </span>
            </div>

            <div className="hidden lg:flex items-center gap-2">
              <span className="text-xs uppercase font-mono font-bold text-slate-400">Overall Blast Risk:</span>
              <span
                className={`text-xs font-mono font-bold px-2 py-0.5 rounded border ${
                  (data?.overall_risk ?? 0) >= 0.7
                    ? 'bg-red-950 text-red-400 border-red-800'
                    : (data?.overall_risk ?? 0) >= 0.3
                    ? 'bg-amber-950 text-amber-400 border-amber-800'
                    : 'bg-emerald-950 text-emerald-400 border-emerald-800'
                }`}
              >
                {((data?.overall_risk ?? 0) * 100).toFixed(0)}%
              </span>
            </div>
          </div>

          {/* Header Action Buttons */}
          <div className="flex items-center gap-2">
            <button
              onClick={handleInjectTelemetry}
              disabled={simulating}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded bg-amber-500/10 border border-amber-500/40 text-amber-300 hover:bg-amber-500/20 transition cursor-pointer"
            >
              <Zap className="h-3.5 w-3.5" />
              {simulating ? 'Injecting...' : 'Inject Attack'}
            </button>

            <button
              onClick={handleExportReport}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded bg-[#1e2638] border border-slate-700 text-slate-200 hover:bg-slate-800 transition cursor-pointer"
            >
              <Download className="h-3.5 w-3.5" />
              Export JSON
            </button>

            <button
              onClick={fetchDashboard}
              className="p-1.5 rounded bg-[#1e2638] border border-slate-700 text-slate-300 hover:bg-slate-800 transition cursor-pointer"
              title="Refresh Telemetry"
            >
              <RefreshCw className="h-3.5 w-3.5" />
            </button>
          </div>
        </header>

        {/* VIEW 1: OVERVIEW PAGE */}
        {activeTab === 'overview' && (
          <div className="flex-1 p-6 overflow-y-auto space-y-6">
            {/* Top 5 Enterprise KPI Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-4">
              <div className="bg-[#121620] border border-[#1e2638] p-4 rounded-xl">
                <span className="text-[10px] font-mono uppercase text-slate-400 block">Threat Level</span>
                <div className="flex items-center justify-between mt-1">
                  <span
                    className={`text-lg font-bold font-mono ${
                      (data?.overall_risk ?? 0) >= 0.7 ? 'text-red-400' : (data?.overall_risk ?? 0) >= 0.3 ? 'text-amber-400' : 'text-emerald-400'
                    }`}
                  >
                    {(data?.overall_risk ?? 0) >= 0.7 ? 'CRITICAL' : (data?.overall_risk ?? 0) >= 0.3 ? 'SUSPICIOUS' : 'NOMINAL'}
                  </span>
                  <span className="text-xs font-mono text-slate-400">{((data?.overall_risk ?? 0) * 100).toFixed(0)}%</span>
                </div>
                <div className="w-full bg-[#1e2638] h-1.5 rounded-full mt-2 overflow-hidden">
                  <div
                    className={`h-full ${
                      (data?.overall_risk ?? 0) >= 0.7 ? 'bg-red-500' : (data?.overall_risk ?? 0) >= 0.3 ? 'bg-amber-500' : 'bg-emerald-500'
                    }`}
                    style={{ width: `${(data?.overall_risk ?? 0) * 100}%` }}
                  />
                </div>
              </div>

              <div className="bg-[#121620] border border-[#1e2638] p-4 rounded-xl">
                <span className="text-[10px] font-mono uppercase text-slate-400 block">Active Investigations</span>
                <span className="text-xl font-bold font-mono text-white mt-1 block">{casesList.length} Active Cases</span>
                <span className="text-[11px] text-cyan-400 font-mono mt-1 block">Primary: CASE-412</span>
              </div>

              <div className="bg-[#121620] border border-[#1e2638] p-4 rounded-xl">
                <span className="text-[10px] font-mono uppercase text-slate-400 block">Telemetry Events</span>
                <span className="text-xl font-bold font-mono text-white mt-1 block">{data?.stats.total_events} Ingested</span>
                <span className="text-[11px] text-slate-400 font-mono mt-1 block">eBPF Syscall Streams</span>
              </div>

              <div className="bg-[#121620] border border-[#1e2638] p-4 rounded-xl">
                <span className="text-[10px] font-mono uppercase text-slate-400 block">MITRE Techniques</span>
                <span className="text-xl font-bold font-mono text-amber-400 mt-1 block">{data?.stats.mitre_count} TTPs Detected</span>
                <span className="text-[11px] text-slate-400 font-mono mt-1 block">T1055, T1041, T1003</span>
              </div>

              <div className="bg-[#121620] border border-[#1e2638] p-4 rounded-xl">
                <span className="text-[10px] font-mono uppercase text-slate-400 block">Assets Under Monitor</span>
                <span className="text-xl font-bold font-mono text-white mt-1 block">1 Target Host</span>
                <span className="text-[11px] text-cyan-300 font-mono mt-1 block">{data?.host_id}</span>
              </div>
            </div>

            {/* Large AI Executive Summary Card */}
            <div className="bg-[#121620] border border-indigo-500/30 rounded-xl p-5 shadow-lg relative overflow-hidden">
              <div className="flex items-center gap-2 text-xs font-mono font-bold text-indigo-400 mb-2">
                <Sparkles className="h-4 w-4" />
                <span>CHRONOS Grounded Investigation Synthesis (Zero Hallucination Guarantee)</span>
              </div>
              <p className="text-sm font-sans leading-relaxed text-slate-200 bg-[#0b0e14] p-4 rounded-lg border border-[#1e2638]">
                {data?.narrative}
              </p>
            </div>

            {/* Three Column Panels (Recent Investigations, Top Threats, MITRE Heatmap Preview) */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Recent Investigations Panel */}
              <div className="bg-[#121620] border border-[#1e2638] rounded-xl p-4 flex flex-col justify-between">
                <div>
                  <h3 className="text-xs font-mono uppercase font-bold text-slate-300 flex items-center gap-2 mb-3">
                    <Folder className="h-4 w-4 text-cyan-400" />
                    Active Investigations
                  </h3>
                  <div className="space-y-2.5">
                    {casesList.map((c) => (
                      <div key={c.case_id} className="p-3 bg-[#0b0e14] rounded-lg border border-[#1e2638] text-xs font-sans">
                        <div className="flex items-center justify-between">
                          <span className="font-mono font-bold text-cyan-300">{c.case_id}</span>
                          <span className="px-1.5 py-0.2 rounded bg-red-950 text-red-400 border border-red-800 text-[10px]">
                            {c.severity}
                          </span>
                        </div>
                        <p className="text-slate-300 mt-1 font-semibold text-xs">{c.title}</p>
                        <span className="text-[10px] font-mono text-slate-500 mt-1 block">Assigned: {c.assigned_to}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Top Threats Panel */}
              <div className="bg-[#121620] border border-[#1e2638] rounded-xl p-4 flex flex-col justify-between">
                <div>
                  <h3 className="text-xs font-mono uppercase font-bold text-slate-300 flex items-center gap-2 mb-3">
                    <Globe className="h-4 w-4 text-indigo-400" />
                    Correlated Threat Intel Hits
                  </h3>
                  <div className="space-y-2.5">
                    {threatIntelFeed.slice(0, 3).map((ioc) => (
                      <div key={ioc.indicator} className="p-3 bg-[#0b0e14] rounded-lg border border-[#1e2638] text-xs">
                        <div className="flex items-center justify-between">
                          <span className="font-mono font-bold text-red-400">{ioc.threat_actor}</span>
                          <span className="text-[10px] font-mono text-amber-400">{ioc.confidence * 100}% Conf</span>
                        </div>
                        <p className="text-slate-300 font-mono text-[11px] mt-1 truncate">{ioc.indicator}</p>
                        <p className="text-slate-400 text-[10px] mt-0.5">{ioc.description}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* MITRE ATT&CK Heatmap Preview */}
              <div className="bg-[#121620] border border-[#1e2638] rounded-xl p-4 flex flex-col justify-between">
                <div>
                  <h3 className="text-xs font-mono uppercase font-bold text-slate-300 flex items-center gap-2 mb-3">
                    <Target className="h-4 w-4 text-amber-400" />
                    Subsystem Risk Matrix
                  </h3>
                  <div className="grid grid-cols-2 gap-2">
                    {data?.threat_heatmap &&
                      Object.entries(data.threat_heatmap).map(([area, val]) => {
                        const score = typeof val === 'number' ? val : (val?.score ?? 0)
                        return (
                          <div key={area} className="p-3 bg-[#0b0e14] border border-[#1e2638] rounded-lg flex flex-col items-center">
                            <span className="text-[10px] font-mono uppercase text-slate-400">{area}</span>
                            <span
                              className={`text-base font-bold font-mono mt-1 ${
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
              </div>
            </div>
          </div>
        )}

        {/* VIEW 2: INVESTIGATIONS PAGE (Graph + Right Inspector Pane) */}
        {activeTab === 'investigations' && (
          <div className="flex-1 grid grid-cols-1 lg:grid-cols-12 overflow-hidden">
            {/* Left Graph Panel */}
            <div className="lg:col-span-8 flex flex-col border-r border-[#1e2638] relative bg-[#090c12]">
              <div className="absolute top-3 left-3 z-10 bg-[#121620] border border-[#1e2638] px-3 py-1.5 rounded-lg text-xs font-mono text-slate-300 shadow-md">
                Interactive Multi-Entity Attack Graph ({nodes.length} Nodes · {edges.length} Edges)
              </div>

              <div className="flex-1 w-full h-full">
                <ReactFlow
                  nodes={nodes}
                  edges={edges}
                  onNodesChange={onNodesChange}
                  onEdgesChange={onEdgesChange}
                  onNodeClick={onNodeClick}
                  nodeTypes={nodeTypes}
                  fitView
                >
                  <Background color="#1e293b" gap={20} size={1} />
                  <Controls className="!m-3" />
                  <MiniMap nodeColor={(n: any) => (n.data?.risk > 0.6 ? '#f43f5e' : '#38bdf8')} maskColor="#0b0e14c0" className="!m-3" />
                </ReactFlow>
              </div>
            </div>

            {/* Right Investigation Pane */}
            <div className="lg:col-span-4 bg-[#121620] p-4 flex flex-col gap-4 overflow-y-auto">
              <div className="border-b border-[#1e2638] pb-3">
                <span className="text-xs font-mono uppercase font-bold text-slate-400 flex items-center gap-2">
                  <Eye className="h-4 w-4 text-cyan-400" />
                  Selected Entity Inspector
                </span>
              </div>

              {selectedNode ? (
                <div className="space-y-4 text-xs font-mono">
                  <div className="p-3 bg-[#0b0e14] rounded-lg border border-[#1e2638]">
                    <span className="text-[10px] text-slate-500 uppercase">Entity Label</span>
                    <p className="text-sm font-bold text-white mt-0.5 break-all">{selectedNode.label}</p>
                    <div className="flex gap-2 mt-2">
                      <span className="px-2 py-0.5 rounded bg-[#1e2638] text-slate-300 text-[10px]">Type: {selectedNode.type}</span>
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          selectedNode.risk >= 0.7 ? 'bg-red-950 text-red-400 border border-red-800' : 'bg-amber-950 text-amber-400'
                        }`}
                      >
                        Risk: {(selectedNode.risk * 100).toFixed(0)}%
                      </span>
                    </div>
                  </div>

                  <div>
                    <span className="text-slate-400 block mb-1">Causal Relationships</span>
                    <div className="space-y-1.5 max-h-40 overflow-y-auto">
                      {data?.graph.edges
                        .filter((e) => e.source === selectedNode.id || e.target === selectedNode.id)
                        .map((e) => (
                          <div key={e.id} className="p-2 rounded bg-[#0b0e14] border border-[#1e2638] text-[11px]">
                            <span className="text-cyan-400">{e.source}</span>
                            <span className="text-slate-500 mx-1">──[{e.relation}]──►</span>
                            <span className="text-amber-400">{e.target}</span>
                          </div>
                        ))}
                    </div>
                  </div>

                  <div>
                    <span className="text-slate-400 block mb-1">Raw Telemetry Attributes</span>
                    <pre className="p-3 bg-[#0b0e14] rounded-lg border border-[#1e2638] text-[11px] text-slate-300 overflow-x-auto max-h-48">
                      {JSON.stringify(selectedNode.metadata, null, 2)}
                    </pre>
                  </div>
                </div>
              ) : (
                <p className="text-xs text-slate-500 font-mono">Select a node in the attack graph to inspect.</p>
              )}
            </div>
          </div>
        )}

        {/* VIEW 3: ATTACK TIMELINE PAGE */}
        {activeTab === 'timeline' && (
          <div className="flex-1 p-6 overflow-y-auto space-y-4">
            <div className="flex flex-col sm:flex-row items-center justify-between gap-4 bg-[#121620] p-4 rounded-xl border border-[#1e2638]">
              <div>
                <h2 className="text-sm font-bold text-white uppercase font-mono flex items-center gap-2">
                  <Calendar className="h-4 w-4 text-cyan-400" />
                  Chronological Attack Progression Timeline
                </h2>
                <p className="text-xs text-slate-400">Sequential attack sequence reconstructor powered by eBPF timestamp streams.</p>
              </div>

              <div className="flex items-center gap-2">
                <input
                  type="text"
                  placeholder="Filter PID, comm..."
                  value={timelineFilter}
                  onChange={(e) => setTimelineFilter(e.target.value)}
                  className="px-3 py-1.5 text-xs bg-[#0b0e14] border border-[#1e2638] rounded-lg text-slate-200 font-mono"
                />
                <select
                  value={minRiskFilter}
                  onChange={(e) => setMinRiskFilter(Number(e.target.value))}
                  className="px-3 py-1.5 text-xs bg-[#0b0e14] border border-[#1e2638] rounded-lg text-slate-200 font-mono"
                >
                  <option value={0}>All Anomaly Scores</option>
                  <option value={0.5}>Score ≥ 0.5 (Suspicious)</option>
                  <option value={0.8}>Score ≥ 0.8 (Critical)</option>
                </select>
              </div>
            </div>

            <div className="space-y-3 font-mono text-xs">
              {filteredTimeline.map((evt, idx) => (
                <div key={idx} className="p-3.5 bg-[#121620] rounded-xl border border-[#1e2638] flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <span className="text-cyan-400 font-semibold">{evt.timestamp}</span>
                    <span className="px-2 py-0.5 rounded bg-[#0b0e14] border border-slate-700 text-slate-200 font-bold">
                      {evt.comm} (PID {evt.pid})
                    </span>
                    <span className="text-slate-300">{evt.event_type}</span>
                  </div>

                  <span
                    className={`px-2 py-0.5 rounded font-bold ${
                      evt.anomaly_score >= 0.7 ? 'bg-red-950 text-red-400 border border-red-800' : 'bg-slate-800 text-slate-400'
                    }`}
                  >
                    Score: {(evt.anomaly_score * 100).toFixed(0)}%
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* VIEW 4: ATTACK GRAPH PAGE */}
        {activeTab === 'graph' && (
          <div className="flex-1 w-full h-full relative bg-[#090c12]">
            <ReactFlow nodes={nodes} edges={edges} onNodesChange={onNodesChange} onEdgesChange={onEdgesChange} onNodeClick={onNodeClick} nodeTypes={nodeTypes} fitView>
              <Background color="#1e293b" gap={20} size={1} />
              <Controls className="!m-3" />
              <MiniMap nodeColor={(n: any) => (n.data?.risk > 0.6 ? '#f43f5e' : '#38bdf8')} maskColor="#0b0e14c0" className="!m-3" />
            </ReactFlow>
          </div>
        )}

        {/* VIEW 5: MITRE ATT&CK PAGE */}
        {activeTab === 'mitre' && (
          <div className="flex-1 p-6 overflow-y-auto space-y-4">
            <div className="mb-4">
              <h2 className="text-sm font-bold text-white uppercase font-mono flex items-center gap-2">
                <Target className="h-4 w-4 text-cyan-400" />
                MITRE ATT&CK Enterprise Kill-Chain Alignments
              </h2>
              <p className="text-xs text-slate-400">Behavioral signatures matched against live eBPF telemetry.</p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 font-mono">
              {data?.mitre_matches.map((m) => (
                <div key={m.technique_id} className="bg-[#121620] border border-[#1e2638] rounded-xl p-4">
                  <div className="flex items-center justify-between">
                    <span className="px-2 py-0.5 rounded bg-red-950 text-red-400 border border-red-800 font-bold text-xs">{m.technique_id}</span>
                    <span className="text-amber-400 text-xs font-bold">{m.confidence}% Conf</span>
                  </div>
                  <h3 className="text-sm font-bold text-white mt-2 font-sans">{m.name}</h3>
                  <p className="text-xs text-slate-300 mt-2 leading-relaxed">{m.description}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* VIEW 6: AI ANALYST PAGE */}
        {activeTab === 'ai_analyst' && (
          <div className="flex-1 p-6 flex flex-col overflow-hidden">
            <div className="mb-3">
              <h2 className="text-sm font-bold text-white uppercase font-mono flex items-center gap-2">
                <BrainCircuit className="h-4 w-4 text-indigo-400" />
                CHRONOS Security Copilot (Grounded AI Analyst)
              </h2>
            </div>

            {/* Suggested Prompt Chips */}
            <div className="flex gap-2 overflow-x-auto pb-3">
              {[
                'What happened?',
                'Explain attack path',
                'Why is this suspicious?',
                'Show attacker objective',
                'Recommend containment',
                'Generate incident report',
              ].map((chip) => (
                <button
                  key={chip}
                  onClick={() => handleSendChat(chip)}
                  className="px-3 py-1 bg-[#121620] hover:bg-indigo-950/60 border border-[#1e2638] text-xs font-mono text-indigo-300 rounded-full transition cursor-pointer whitespace-nowrap"
                >
                  {chip}
                </button>
              ))}
            </div>

            {/* Chat Conversation Box */}
            <div className="flex-1 bg-[#121620] border border-[#1e2638] rounded-xl p-4 flex flex-col overflow-hidden">
              <div className="flex-1 overflow-y-auto space-y-4 pr-2">
                {chatMessages.map((msg) => (
                  <div key={msg.id} className={`flex gap-3 ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                    {msg.role === 'assistant' && (
                      <div className="h-7 w-7 rounded-lg bg-indigo-950 border border-indigo-800 flex items-center justify-center text-indigo-400 shrink-0">
                        <Sparkles className="h-3.5 w-3.5" />
                      </div>
                    )}
                    <div
                      className={`p-3.5 rounded-xl max-w-2xl text-xs font-mono leading-relaxed ${
                        msg.role === 'user' ? 'bg-indigo-600 text-white' : 'bg-[#0b0e14] border border-[#1e2638] text-slate-200 whitespace-pre-wrap'
                      }`}
                    >
                      {msg.content}
                    </div>
                  </div>
                ))}
              </div>

              <form onSubmit={(e) => { e.preventDefault(); handleSendChat(); }} className="mt-4 pt-3 border-t border-[#1e2638] flex gap-2">
                <input
                  type="text"
                  placeholder="Ask AI Analyst..."
                  value={chatInput}
                  onChange={(e) => setChatInput(e.target.value)}
                  className="flex-1 px-3 py-2 text-xs bg-[#0b0e14] border border-[#1e2638] rounded-lg text-slate-200 font-mono"
                />
                <button type="submit" disabled={chatLoading} className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white font-bold text-xs rounded-lg font-mono">
                  Send
                </button>
              </form>
            </div>
          </div>
        )}

        {/* VIEW 7: RESPONSE CENTER PAGE */}
        {activeTab === 'response_center' && (
          <div className="flex-1 p-6 overflow-y-auto space-y-6">
            <div className="mb-4">
              <h2 className="text-sm font-bold text-white uppercase font-mono flex items-center gap-2">
                <ShieldAlert className="h-4 w-4 text-red-400" />
                Response & Containment Center
              </h2>
              <p className="text-xs text-slate-400">Policy-governed remediation actions with human-in-the-loop authorization.</p>
            </div>

            {/* Quick Action Buttons */}
            <div className="grid grid-cols-2 md:grid-cols-5 gap-3 font-mono text-xs">
              {['Kill Process', 'Block IP', 'Quarantine File', 'Disable Persistence', 'Isolate Host'].map((act) => (
                <button key={act} className="p-3 bg-[#121620] hover:bg-red-950/40 border border-[#1e2638] hover:border-red-800 rounded-xl text-slate-200 font-bold transition flex items-center justify-center gap-2 cursor-pointer">
                  <Lock className="h-3.5 w-3.5 text-red-400" />
                  [{act}]
                </button>
              ))}
            </div>

            {/* Pending Approvals */}
            <div className="bg-[#121620] border border-[#1e2638] rounded-xl p-5 space-y-3 font-mono">
              <h3 className="text-xs uppercase font-bold text-amber-400 mb-2">Pending Human Authorization Queue</h3>
              {data?.response_actions
                .filter((a) => a.status === 'pending_approval')
                .map((act) => (
                  <div key={act.action_id} className="p-3 bg-[#0b0e14] rounded-lg border border-amber-900/60 text-xs flex items-center justify-between">
                    <div>
                      <span className="font-bold text-white">{act.action_type}</span>
                      <p className="text-slate-400 text-[11px]">Policy: {act.policy_name}</p>
                    </div>
                    <div className="flex gap-2">
                      <button onClick={() => handleApproveAction(act.action_id, true)} className="px-3 py-1 bg-emerald-600 hover:bg-emerald-500 text-white rounded font-bold text-xs cursor-pointer">
                        Approve
                      </button>
                      <button onClick={() => handleApproveAction(act.action_id, false)} className="px-3 py-1 bg-slate-800 hover:bg-red-950 text-slate-300 rounded font-bold text-xs cursor-pointer">
                        Reject
                      </button>
                    </div>
                  </div>
                ))}
            </div>
          </div>
        )}

        {/* VIEW 8: CASES PAGE */}
        {activeTab === 'cases' && (
          <div className="flex-1 p-6 overflow-y-auto space-y-4 font-mono">
            <div className="mb-4">
              <h2 className="text-sm font-bold text-white uppercase flex items-center gap-2">
                <Folder className="h-4 w-4 text-cyan-400" />
                Enterprise Case Workspace
              </h2>
            </div>
            {casesList.map((c) => (
              <div key={c.case_id} className="p-5 bg-[#121620] border border-[#1e2638] rounded-xl">
                <div className="flex justify-between items-start border-b border-[#1e2638] pb-3">
                  <div>
                    <span className="px-2 py-0.5 rounded bg-red-950 text-red-400 border border-red-800 font-bold text-xs">{c.case_id}</span>
                    <h3 className="text-base font-bold text-white mt-2">{c.title}</h3>
                  </div>
                  <span className="text-xs text-cyan-400">Assigned: {c.assigned_to}</span>
                </div>
                <p className="text-xs text-emerald-400 mt-3 font-semibold">Verdict: {c.verdict}</p>
              </div>
            ))}
          </div>
        )}

        {/* VIEW 9: SETTINGS PAGE */}
        {activeTab === 'settings' && (
          <div className="flex-1 p-6 overflow-y-auto space-y-4 font-mono">
            <h2 className="text-sm font-bold text-white uppercase flex items-center gap-2">
              <SettingsIcon className="h-4 w-4 text-slate-400" />
              CHRONOS System Configuration & Asset Weights
            </h2>
            <div className="p-5 bg-[#121620] border border-[#1e2638] rounded-xl text-xs space-y-3">
              <p className="text-slate-300">CO-RE eBPF Probes Status: ACTIVE (execve, fork, mprotect, ptrace, connect)</p>
              <p className="text-slate-300">Asset Risk Multiplier (Domain Controller): 1.5x</p>
              <p className="text-slate-300">Asset Risk Multiplier (Workstation): 1.0x</p>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
