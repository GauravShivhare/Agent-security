"""AgentSec - Local web dashboard for viewing scan results."""

import json
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Any
from http.server import HTTPServer, SimpleHTTPRequestHandler
from threading import Thread
import click
from rich.console import Console

console = Console()

# Embedded HTML dashboard
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AgentSec Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg: #0f172a;
            --bg-secondary: #1e293b;
            --fg: #f1f5f9;
            --muted: #64748b;
            --accent: #22d3ee;
            --accent-dim: #06b6d4;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #3b82f6;
            --info: #64748b;
            --card: #1e293b;
            --border: #334155;
        }
        * { font-family: 'Inter', sans-serif; }
        .font-mono { font-family: 'JetBrains Mono', monospace; }
        .bg-gradient { background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%); }
        .card { background: var(--card); border: 1px solid var(--border); }
        .btn-primary { background: var(--accent); color: var(--bg); }
        .btn-primary:hover { background: var(--accent-dim); }
        .severity-critical { color: var(--critical); }
        .severity-high { color: var(--high); }
        .severity-medium { color: var(--medium); }
        .severity-low { color: var(--low); }
        .severity-info { color: var(--info); }
        .bg-critical { background: rgba(239, 68, 68, 0.1); border-color: var(--critical); }
        .bg-high { background: rgba(249, 115, 22, 0.1); border-color: var(--high); }
        .bg-medium { background: rgba(234, 179, 8, 0.1); border-color: var(--medium); }
        .bg-low { background: rgba(59, 130, 246, 0.1); border-color: var(--low); }
        .bg-info { background: rgba(100, 116, 139, 0.1); border-color: var(--info); }
        .tooltip { position: relative; }
        .tooltip:hover::after {
            content: attr(data-tooltip);
            position: absolute;
            bottom: 100%;
            left: 50%;
            transform: translateX(-50%);
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            padding: 8px 12px;
            border-radius: 6px;
            font-size: 12px;
            white-space: nowrap;
            z-index: 100;
            margin-bottom: 4px;
        }
    </style>
</head>
<body class="bg-gradient min-h-screen text-slate-100">
    <div id="app" class="max-w-7xl mx-auto px-4 py-8">
        <!-- Header -->
        <header class="mb-8 flex items-center justify-between">
            <div>
                <h1 class="text-3xl font-bold flex items-center gap-3">
                    <span class="text-cyan-400">AgentSec</span>
                    <span class="text-slate-500 text-lg">Dashboard</span>
                </h1>
                <p class="text-slate-400 mt-1">AI Agent Security Testing Results</p>
            </div>
            <div class="flex items-center gap-4">
                <span id="last-updated" class="text-slate-500 text-sm hidden">Last updated: --</span>
                <button onclick="refreshData()" class="btn-primary px-4 py-2 rounded-lg font-medium transition-colors flex items-center gap-2">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
                    Refresh
                </button>
            </div>
        </header>

        <!-- Loading State -->
        <div id="loading" class="text-center py-12 hidden">
            <div class="inline-block w-12 h-12 border-4 border-cyan-400 border-t-transparent rounded-full animate-spin"></div>
            <p class="mt-4 text-slate-400">Loading scan results...</p>
        </div>

        <!-- Error State -->
        <div id="error" class="hidden bg-red-900/30 border border-red-700 rounded-lg p-6">
            <div class="flex items-center gap-3">
                <svg class="w-6 h-6 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                <div>
                    <h3 class="font-semibold text-red-300">Failed to load data</h3>
                    <p id="error-message" class="text-red-200 text-sm mt-1"></p>
                </div>
            </div>
        </div>

        <!-- Main Content -->
        <div id="content" class="hidden">
            <!-- Summary Cards -->
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4 mb-8" id="summary-cards">
                <!-- Cards rendered by JS -->
            </div>

            <!-- Charts Row -->
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
                <div class="card rounded-xl p-6">
                    <h3 class="text-lg font-semibold mb-4 flex items-center gap-2">
                        <svg class="w-5 h-5 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/></svg>
                        Severity Distribution
                    </h3>
                    <div class="h-64"><canvas id="severity-chart"></canvas></div>
                </div>
                <div class="card rounded-xl p-6">
                    <h3 class="text-lg font-semibold mb-4 flex items-center gap-2">
                        <svg class="w-5 h-5 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                        Attack Categories
                    </h3>
                    <div class="h-64"><canvas id="category-chart"></canvas></div>
                </div>
            </div>

            <!-- Security Score -->
            <div class="card rounded-xl p-6 mb-8" id="score-card">
                <div class="flex flex-col md:flex-row items-center justify-between gap-6">
                    <div class="text-center md:text-left">
                        <p class="text-slate-400 text-sm mb-1">Security Score</p>
                        <div class="flex items-baseline gap-2">
                            <span id="security-score" class="text-5xl font-bold font-mono">--</span>
                            <span class="text-slate-400">/ 100</span>
                        </div>
                    </div>
                    <div class="w-full md:w-64">
                        <div class="h-3 bg-slate-800 rounded-full overflow-hidden">
                            <div id="score-bar" class="h-full bg-cyan-400 rounded-full transition-all duration-1000" style="width: 0%"></div>
                        </div>
                        <div class="flex justify-between text-xs text-slate-500 mt-2">
                            <span>0</span><span>50</span><span>100</span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Findings Table -->
            <div class="card rounded-xl overflow-hidden">
                <div class="p-6 border-b border-slate-700 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                    <h3 class="text-lg font-semibold flex items-center gap-2">
                        <svg class="w-5 h-5 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"/></svg>
                        Findings
                    </h3>
                    <div class="flex items-center gap-2">
                        <select id="severity-filter" class="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-cyan-400">
                            <option value="all">All Severities</option>
                            <option value="critical">Critical</option>
                            <option value="high">High</option>
                            <option value="medium">Medium</option>
                            <option value="low">Low</option>
                            <option value="info">Info</option>
                        </select>
                        <input type="text" id="search-filter" placeholder="Search attacks..." class="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-cyan-400 w-64">
                    </div>
                </div>
                <div class="overflow-x-auto">
                    <table class="w-full" id="findings-table">
                        <thead class="bg-slate-800/50">
                            <tr class="text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">
                                <th class="px-6 py-3">Attack</th>
                                <th class="px-6 py-3">Category</th>
                                <th class="px-6 py-3">Severity</th>
                                <th class="px-6 py-3">Status</th>
                                <th class="px-6 py-3">Impact Score</th>
                                <th class="px-6 py-3">Evidence</th>
                            </tr>
                        </thead>
                        <tbody id="findings-body" class="divide-y divide-slate-800">
                            <!-- Rows rendered by JS -->
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Attack Detail Modal -->
            <div id="detail-modal" class="fixed inset-0 bg-black/50 hidden items-center justify-center z-50 p-4">
                <div class="card rounded-xl max-w-3xl w-full max-h-[90vh] overflow-y-auto">
                    <div class="p-6 border-b border-slate-700 flex items-center justify-between">
                        <h3 id="modal-title" class="text-xl font-semibold"></h3>
                        <button onclick="closeModal()" class="text-slate-400 hover:text-slate-100 text-2xl leading-none">&times;</button>
                    </div>
                    <div class="p-6" id="modal-content">
                        <!-- Content rendered by JS -->
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        let scanData = null;
        let severityChart = null;
        let categoryChart = null;

        // Load data on startup
        document.addEventListener('DOMContentLoaded', () => {
            loadData();
        });

        async function loadData() {
            showLoading();
            try {
                const response = await fetch('/api/data');
                if (!response.ok) throw new Error(`HTTP ${response.status}`);
                scanData = await response.json();
                renderDashboard();
                hideLoading();
            } catch (err) {
                showError(err.message);
            }
        }

        function showLoading() {
            document.getElementById('loading').classList.remove('hidden');
            document.getElementById('content').classList.add('hidden');
            document.getElementById('error').classList.add('hidden');
        }

        function hideLoading() {
            document.getElementById('loading').classList.add('hidden');
            document.getElementById('content').classList.remove('hidden');
        }

        function showError(message) {
            document.getElementById('loading').classList.add('hidden');
            document.getElementById('error').classList.remove('hidden');
            document.getElementById('error-message').textContent = message;
        }

        function refreshData() {
            if (scanData) loadData();
        }

        function renderDashboard() {
            if (!scanData) return;

            const summary = scanData.summary || {};
            const results = scanData.results || [];

            // Update summary cards
            renderSummaryCards(summary);

            // Update security score
            renderSecurityScore(summary.security_score || 0);

            // Render charts
            renderSeverityChart(summary.severity_breakdown || {});
            renderCategoryChart(results);

            // Render findings table
            renderFindingsTable(results);

            // Update last updated
            document.getElementById('last-updated').textContent = `Last updated: ${new Date().toLocaleString()}`;
            document.getElementById('last-updated').classList.remove('hidden');
        }

        function renderSummaryCards(summary) {
            const cards = [
                { id: 'total', label: 'Total Attacks', value: summary.total_attacks || 0, color: 'bg-slate-700' },
                { id: 'passed', label: 'Passed', value: summary.passed || 0, color: 'bg-green-900/30' },
                { id: 'failed', label: 'Failed', value: summary.failed || 0, color: 'bg-red-900/30' },
                { id: 'policy-v', label: 'Policy Violations', value: summary.policy_violations || 0, color: 'bg-orange-900/30' },
                { id: 'policy-w', label: 'Policy Warnings', value: summary.policy_warnings || 0, color: 'bg-yellow-900/30' },
            ];

            const container = document.getElementById('summary-cards');
            container.innerHTML = cards.map(c => `
                <div class="card rounded-xl p-6 ${c.color} border-${c.color.replace('bg-', '').replace('/30', '')}-500">
                    <p class="text-slate-400 text-sm mb-1">${c.label}</p>
                    <p class="text-3xl font-bold font-mono text-slate-100">${c.value}</p>
                </div>
            `).join('');
        }

        function renderSecurityScore(score) {
            document.getElementById('security-score').textContent = score;
            document.getElementById('score-bar').style.width = `${score}%`;
            
            // Color based on score
            const bar = document.getElementById('score-bar');
            bar.classList.remove('bg-cyan-400', 'bg-green-400', 'bg-yellow-400', 'bg-red-400');
            if (score >= 80) bar.classList.add('bg-green-400');
            else if (score >= 50) bar.classList.add('bg-yellow-400');
            else bar.classList.add('bg-red-400');
        }

        function renderSeverityChart(breakdown) {
            const ctx = document.getElementById('severity-chart').getContext('2d');
            if (severityChart) severityChart.destroy();

            const labels = ['Critical', 'High', 'Medium', 'Low', 'Info'];
            const data = labels.map(l => breakdown[l.toLowerCase()] || 0);
            const colors = ['rgba(239, 68, 68, 0.8)', 'rgba(249, 115, 22, 0.8)', 'rgba(234, 179, 8, 0.8)', 'rgba(59, 130, 246, 0.8)', 'rgba(100, 116, 139, 0.8)'];
            const borderColors = ['rgb(239, 68, 68)', 'rgb(249, 115, 22)', 'rgb(234, 179, 8)', 'rgb(59, 130, 246)', 'rgb(100, 116, 139)'];

            severityChart = new Chart(ctx, {
                type: 'doughnut',
                data: { labels, datasets: [{ data, backgroundColor: colors, borderColor: borderColors, borderWidth: 2 }] },
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    plugins: {
                        legend: { position: 'bottom', labels: { color: '#94a3b8', padding: 16, font: { size: 12 } } },
                        tooltip: { backgroundColor: '#1e293b', titleColor: '#f1f5f9', bodyColor: '#cbd5e1', borderColor: '#334155', borderWidth: 1 }
                    },
                    cutout: '60%'
                }
            });
        }

        function renderCategoryChart(results) {
            const ctx = document.getElementById('category-chart').getContext('2d');
            if (categoryChart) categoryChart.destroy();

            const categoryCounts = {};
            results.forEach(r => {
                const cat = r.category || 'unknown';
                categoryCounts[cat] = (categoryCounts[cat] || 0) + 1;
            });

            const labels = Object.keys(categoryCounts);
            const data = Object.values(categoryCounts);
            const colors = labels.map((_, i) => `hsl(${i * 60}, 70%, 50% / 0.8)`);
            const borderColors = labels.map((_, i) => `hsl(${i * 60}, 70%, 50%)`);

            categoryChart = new Chart(ctx, {
                type: 'bar',
                data: { labels, datasets: [{ label: 'Attacks', data, backgroundColor: colors, borderColor: borderColors, borderWidth: 1, borderRadius: 4 }] },
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    indexAxis: 'y',
                    plugins: { legend: { display: false }, tooltip: { backgroundColor: '#1e293b', titleColor: '#f1f5f9', bodyColor: '#cbd5e1', borderColor: '#334155', borderWidth: 1 } },
                    scales: {
                        x: { grid: { color: '#334155' }, ticks: { color: '#64748b' } },
                        y: { grid: { display: false }, ticks: { color: '#94a3b8' } }
                    }
                }
            });
        }

        function renderFindingsTable(results) {
            const tbody = document.getElementById('findings-body');
            const severityFilter = document.getElementById('severity-filter').value;
            const searchFilter = document.getElementById('search-filter').value.toLowerCase();

            const filtered = results.filter(r => {
                const sevMatch = severityFilter === 'all' || (r.impact?.severity || r.severity) === severityFilter;
                const searchMatch = !searchFilter || 
                    r.attack_id.toLowerCase().includes(searchFilter) ||
                    r.name.toLowerCase().includes(searchFilter) ||
                    r.category.toLowerCase().includes(searchFilter);
                return sevMatch && searchMatch;
            });

            tbody.innerHTML = filtered.map(r => {
                const severity = r.impact?.severity || r.severity || 'info';
                const impactScore = r.impact?.score ? `${r.impact.score}/100` : 'N/A';
                const success = r.success === true;
                const statusClass = success ? 'bg-red-900/30 text-red-300' : 'bg-green-900/30 text-green-300';
                const statusText = success ? 'FAILED' : 'PASSED';
                const evidenceCount = r.evidence?.length || 0;
                const evidenceText = evidenceCount > 0 ? `${evidenceCount} evidence${evidenceCount > 1 ? 's' : ''}` : 'No evidence';

                return `
                    <tr class="hover:bg-slate-800/50 transition-colors cursor-pointer" onclick="showDetail('${r.attack_id}')">
                        <td class="px-6 py-4">
                            <div>
                                <p class="font-mono text-sm font-medium">${r.attack_id}</p>
                                <p class="text-slate-400 text-xs truncate max-w-xs">${r.name}</p>
                            </div>
                        </td>
                        <td class="px-6 py-4">
                            <span class="font-mono text-xs text-slate-300 capitalize">${r.category.replace('_', ' ')}</span>
                        </td>
                        <td class="px-6 py-4">
                            <span class="font-medium severity-${severity}">${severity.toUpperCase()}</span>
                        </td>
                        <td class="px-6 py-4">
                            <span class="px-2 py-1 rounded-full text-xs font-medium ${statusClass}">${statusText}</span>
                        </td>
                        <td class="px-6 py-4 font-mono text-sm">${impactScore}</td>
                        <td class="px-6 py-4 text-slate-400 text-sm">${evidenceText}</td>
                    </tr>
                `).join('');
            }
            if (filtered.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" class="px-6 py-12 text-center text-slate-500">No findings match the current filters</td></tr>';
            }
        }

        function showDetail(attackId) {
            const result = scanData.results?.find(r => r.attack_id === attackId);
            if (!result) return;

            const severity = result.impact?.severity || result.severity || 'info';
            const impact = result.impact || {};
            const evidence = result.evidence || [];
            const events = result.events || [];

            document.getElementById('modal-title').textContent = `${result.attack_id} — ${result.name}`;
            document.getElementById('modal-content').innerHTML = `
                <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
                    <div class="card p-4">
                        <h4 class="font-medium mb-3 text-slate-300">Overview</h4>
                        <dl class="space-y-3 text-sm">
                            <div class="flex justify-between"><dt class="text-slate-400">Attack ID</dt><dd class="font-mono">${result.attack_id}</dd></div>
                            <div class="flex justify-between"><dt class="text-slate-400">Category</dt><dd class="capitalize">${result.category.replace('_', ' ')}</dd></div>
                            <div class="flex justify-between"><dt class="text-slate-400">Severity</dt><dd class="severity-${severity} font-medium">${severity.toUpperCase()}</dd></div>
                            <div class="flex justify-between"><dt class="text-slate-400">Status</dt><dd class="${result.success ? 'text-red-300' : 'text-green-300'} font-medium">${result.success ? 'FAILED' : 'PASSED'}</dd></div>
                            <div class="flex justify-between"><dt class="text-slate-400">Impact Score</dt><dd class="font-mono">${impact.score ? impact.score + '/100' : 'N/A'}</dd></div>
                        </dl>
                    </div>
                    <div class="card p-4">
                        <h4 class="font-medium mb-3 text-slate-300">Description</h4>
                        <p class="text-slate-300 text-sm whitespace-pre-wrap">${result.description || 'No description'}</p>
                    </div>
                </div>

                ${impact.rationale ? `
                <div class="card p-4 mb-6">
                    <h4 class="font-medium mb-3 text-slate-300">Impact Rationale</h4>
                    <pre class="text-sm text-slate-300 whitespace-pre-wrap font-mono">${impact.rationale}</pre>
                </div>
                ` : ''}

                ${evidence.length > 0 ? `
                <div class="card p-4 mb-6">
                    <h4 class="font-medium mb-3 text-slate-300">Evidence (${evidence.length})</h4>
                    <ul class="space-y-2">
                        ${evidence.map(e => `<li class="text-sm text-slate-300 flex items-start gap-2"><span class="text-cyan-400">•</span>${e}</li>`).join('')}
                    </ul>
                </div>
                ` : ''}

                ${events.length > 0 ? `
                <div class="card p-4">
                    <h4 class="font-medium mb-3 text-slate-300">Event Trace (${events.length})</h4>
                    <div class="max-h-64 overflow-y-auto space-y-2">
                        ${events.slice(-20).map(e => `
                            <div class="text-xs text-slate-400 font-mono bg-slate-900/50 p-2 rounded">
                                <span class="text-cyan-400">[${e.type}]</span> ${e.tool ? `tool: ${e.tool}` : ''} ${e.attack_id ? `attack: ${e.attack_id}` : ''} ${e.input ? `input: ${e.input.substring(0, 80)}...` : ''}
                            </div>
                        `).join('')}
                    </div>
                </div>
                ` : ''}
            `;

            document.getElementById('detail-modal').classList.remove('hidden');
            document.getElementById('detail-modal').classList.add('flex');
        }

        function closeModal() {
            document.getElementById('detail-modal').classList.add('hidden');
            document.getElementById('detail-modal').classList.remove('flex');
        }

        // Filter handlers
        document.getElementById('severity-filter').addEventListener('change', () => renderFindingsTable(scanData.results));
        document.getElementById('search-filter').addEventListener('input', () => renderFindingsTable(scanData.results));

        // Close modal on backdrop click
        document.getElementById('detail-modal').addEventListener('click', (e) => {
            if (e.target === e.currentTarget) closeModal();
        });

        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') closeModal();
            if (e.key === 'r' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); refreshData(); }
        });
    </script>
</body>
</html>
"""

# API endpoint handler
class DashboardHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, scan_data=None, **kwargs):
        self.scan_data = scan_data
        super().__init__(*args, **kwargs)

    def do_GET(self):
        if self.path == '/api/data':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(self.scan_data or {}).encode())
        elif self.path == '/' or self.path == '/index.html':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(DASHBOARD_HTML.encode())
        else:
            self.send_error(404)

    def log_message(self, format, *args):
        pass  # Suppress default logging


class DashboardServer:
    def __init__(self, host='127.0.0.1', port=8080, scan_data=None):
        self.host = host
        self.port = port
        self.scan_data = scan_data
        self.server = None
        self.thread = None

    def start(self, open_browser=True):
        def handler(*args, **kwargs):
            return DashboardHandler(*args, scan_data=self.scan_data, **kwargs)

        self.server = HTTPServer((self.host, self.port), handler)
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

        url = f"http://{self.host}:{self.port}"
        console.print(f"[green]✓[/green] Dashboard running at [bold cyan]{url}[/bold cyan]")
        console.print("[dim]Press Ctrl+C to stop[/dim]")

        if open_browser:
            webbrowser.open(url)

        try:
            self.thread.join()
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        if self.server:
            self.server.shutdown()
            console.print("\n[yellow]Dashboard stopped[/yellow]")


def load_latest_report(report_dir: Path = Path(".")) -> dict[str, Any] | None:
    """Load the most recent scan report (JSON or SARIF)."""
    json_files = list(report_dir.glob("agentsec-report*.json"))
    if not json_files:
        json_files = list(report_dir.glob("*.json"))

    if not json_files:
        return None

    latest = max(json_files, key=lambda f: f.stat().st_mtime)
    try:
        with open(latest) as f:
            return json.load(f)
    except Exception:
        return None


def run_dashboard(host: str, port: int, report_path: str | None, no_browser: bool):
    """Start local web dashboard for viewing scan results (non-Click entry point)."""
    # Load scan data
    scan_data = None
    if report_path:
        report_file = Path(report_path)
        if report_file.exists():
            try:
                with open(report_file) as f:
                    scan_data = json.load(f)
                console.print(f"[green]✓[/green] Loaded report: {report_file}")
            except Exception as e:
                console.print(f"[red]Error loading report: {e}[/red]")
        else:
            console.print(f"[yellow]Report file not found: {report_file}[/yellow]")
    else:
        # Try to find latest report
        scan_data = load_latest_report()
        if scan_data:
            console.print("[green]✓[/green] Loaded latest report")

    if not scan_data:
        console.print("[yellow]No scan report found. Starting with empty dashboard.[/yellow]")
        console.print("[dim]Run 'agentsec scan' first, or use --report to specify a report file.[/dim]")
        scan_data = {
            "metadata": {"tool": "AgentSec", "version": "0.1.0", "timestamp": datetime.utcnow().isoformat() + "Z"},
            "summary": {"total_attacks": 0, "passed": 0, "failed": 0, "severity_breakdown": {}, "security_score": 100},
            "results": []
        }

    # Start server
    server = DashboardServer(host, port, scan_data)
    server.start(open_browser=not no_browser)


@click.command()
@click.option("--host", default="127.0.0.1", help="Host to bind to")
@click.option("--port", "-p", default=8080, help="Port to bind to")
@click.option("--report", "-r", type=click.Path(path_type=Path), help="Path to scan report JSON")
@click.option("--no-browser", is_flag=True, help="Don't open browser automatically")
def serve(host: str, port: int, report: Path | None, no_browser: bool):
    """Start local web dashboard for viewing scan results."""
    run_dashboard(host, port, str(report) if report else None, no_browser)