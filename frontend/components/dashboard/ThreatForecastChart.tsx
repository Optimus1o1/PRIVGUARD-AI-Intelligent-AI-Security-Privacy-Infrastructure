"use client";

import React from "react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { Shield } from "lucide-react";

interface TimelineItem {
  date: string;
  requests: number;
  threats: number;
}

interface ThreatForecastChartProps {
  data: TimelineItem[];
}

export const ThreatForecastChart: React.FC<ThreatForecastChartProps> = ({ data }) => {
  const chartData =
    data && data.length > 0
      ? data.map((d) => ({
          ...d,
          formattedDate: d.date.slice(5), // MM-DD
        }))
      : [
          { date: "Day 1", formattedDate: "01", requests: 0, threats: 0 },
          { date: "Day 2", formattedDate: "02", requests: 0, threats: 0 },
        ];

  return (
    <div className="bg-card border border-border rounded-xl p-5 flex flex-col justify-between shadow-sm">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4 text-cyan-400" />
          <span className="text-xs font-semibold uppercase tracking-wider text-slate">
            AI Threat & Traffic Velocity
          </span>
        </div>
        <div className="flex items-center gap-4 text-xs">
          <div className="flex items-center gap-1.5 text-slate">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-500" />
            <span>AI Requests</span>
          </div>
          <div className="flex items-center gap-1.5 text-slate">
            <span className="w-2.5 h-2.5 rounded-full bg-red-400" />
            <span>Threats Intercepted</span>
          </div>
        </div>
      </div>

      <div className="h-56 w-full pt-2">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
            <defs>
              <linearGradient id="reqGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#06B6D4" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#06B6D4" stopOpacity={0.0} />
              </linearGradient>
              <linearGradient id="threatGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#EF4444" stopOpacity={0.4} />
                <stop offset="95%" stopColor="#EF4444" stopOpacity={0.0} />
              </linearGradient>
            </defs>
            <XAxis
              dataKey="formattedDate"
              stroke="#8B9099"
              fontSize={10}
              tickLine={false}
              axisLine={false}
            />
            <YAxis
              stroke="#8B9099"
              fontSize={10}
              tickLine={false}
              axisLine={false}
              allowDecimals={false}
            />
            <Tooltip
              content={({ active, payload, label }) => {
                if (active && payload && payload.length) {
                  return (
                    <div className="bg-surface border border-border rounded-lg p-2.5 shadow-xl text-xs space-y-1">
                      <div className="font-mono text-slate text-[10px]">{label}</div>
                      <div className="text-cyan-400 font-semibold">
                        Requests: {payload[0]?.value}
                      </div>
                      <div className="text-red-400 font-semibold">
                        Blocked Threats: {payload[1]?.value}
                      </div>
                    </div>
                  );
                }
                return null;
              }}
            />
            <Area
              type="monotone"
              dataKey="requests"
              stroke="#06B6D4"
              strokeWidth={2}
              fillOpacity={1}
              fill="url(#reqGradient)"
            />
            <Area
              type="monotone"
              dataKey="threats"
              stroke="#EF4444"
              strokeWidth={2}
              fillOpacity={1}
              fill="url(#threatGradient)"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      <div className="flex items-center justify-between text-[11px] text-slate/70 pt-3 border-t border-border/60">
        <span>Window: Last 7 Days (Persisted Audit History)</span>
        <span className="font-mono text-cyan-400">Zero Raw Content Logged</span>
      </div>
    </div>
  );
};

