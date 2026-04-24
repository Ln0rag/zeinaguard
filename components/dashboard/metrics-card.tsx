'use client';

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { ArrowDown, ArrowUp } from 'lucide-react';

interface MetricsCardProps {
  title: string;
  value: number | string;
  description?: string;
  icon?: React.ReactNode;
  trend?: {
    value: number;
    label: string;
    isPositive?: boolean;
  };
  bgColor?: string;
  textColor?: string;
  borderColor?: string;
}

export function MetricsCard({
  title,
  value,
  description,
  icon,
  trend,
  bgColor = 'bg-slate-800',
  textColor = 'text-slate-100',
  borderColor = 'border-slate-700',
}: MetricsCardProps) {
  return (
    <Card className={`${bgColor} border-2 ${borderColor}`}>
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle className={`text-sm font-semibold ${textColor}`}>{title}</CardTitle>
          {icon && <div className="opacity-50">{icon}</div>}
        </div>
      </CardHeader>
      <CardContent>
        <div className="flex items-baseline justify-between">
          <div>
            <div className={`text-3xl font-bold ${textColor}`}>{value}</div>
            {description && <p className="text-xs text-slate-400 mt-1">{description}</p>}
          </div>
          {trend && (
            <div className={`flex items-center gap-1 text-xs ${trend.isPositive ? 'text-red-400' : 'text-green-400'}`}>
              {trend.isPositive ? <ArrowUp className="w-3 h-3" /> : <ArrowDown className="w-3 h-3" />}
              <span>{trend.value}% {trend.label}</span>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
