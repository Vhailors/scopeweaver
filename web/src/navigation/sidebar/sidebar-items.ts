import { translate as swt } from "@/i18n/runtime";
import {
  Activity,
  Ban,
  BellRing,
  Bot,
  Brain,
  Bug,
  ClipboardList,
  FolderOpen,
  FolderSync,
  LayoutDashboard,
  type LucideIcon,
  MessageSquare,
  Network,
  Plug,
  Radio,
  ScrollText,
  Settings2,
  ShieldAlert,
  Sparkles,
  Target,
  Terminal,
  Wrench,
} from "lucide-react";

export type NavBadge = "new" | "soon";

export interface NavSubItem {
  id: string;
  title: string;
  url: string;
  icon?: LucideIcon;
  badge?: NavBadge;
  disabled?: boolean;
  newTab?: boolean;
}

interface NavItemBase {
  id: string;
  title: string;
  icon?: LucideIcon;
  badge?: NavBadge;
  disabled?: boolean;
  newTab?: boolean;
}

export interface NavMainLinkItem extends NavItemBase {
  url: string;
  subItems?: never;
}

export interface NavMainParentItem extends NavItemBase {
  subItems: NavSubItem[];
}

export type NavMainItem = NavMainLinkItem | NavMainParentItem;

export interface NavGroup {
  id: number;
  label?: string;
  items: NavMainItem[];
}

export const sidebarItems: NavGroup[] = [
  {
    id: 1,
    get label() { return swt("interface.m2870"); },
    items: [
      { id: "dashboard", get title() { return swt("interface.m2871"); }, url: "/dashboard", icon: LayoutDashboard },
      { id: "chat", get title() { return swt("interface.m2872"); }, url: "/chat", icon: MessageSquare },
      { id: "tasks", get title() { return swt("interface.m0190"); }, url: "/function/tasks", icon: Target },
      { id: "vulnerabilities", get title() { return swt("vulnerability.title"); }, url: "/vulnerabilities", icon: ShieldAlert },
      { id: "findings", get title() { return swt("interface.m0188"); }, url: "/function/findings", icon: Bug },
      { id: "traffic", get title() { return swt("interface.m1067"); }, url: "/function/traffic", icon: Activity },
      { id: "commands", get title() { return swt("interface.m0287"); }, url: "/function/commands", icon: Terminal },
      { id: "llm-records", get title() { return swt("interface.m0426"); }, url: "/function/llm-records", icon: Radio },
      { id: "assets", get title() { return swt("interface.m0222"); }, url: "/function/assets", icon: Network },
      { id: "sync", get title() { return swt("interface.m0445"); }, url: "/function/sync", icon: FolderSync },
      { id: "workspace", get title() { return swt("interface.m1113"); }, url: "/function/workspace", icon: FolderOpen },
    ],
  },
  {
    id: 2,
    get label() { return swt("interface.m1848"); },
    items: [
      { id: "llm", title: "LLM", url: "/system/llm", icon: Brain },
      { id: "agents", get title() { return swt("english.e082"); }, url: "/system/agents", icon: Bot },
      { id: "mcp", title: "MCP", url: "/system/mcp", icon: Plug },
      { id: "skills", get title() { return swt("english.e084"); }, url: "/system/skills", icon: Sparkles },
      { id: "tools", get title() { return swt("interface.m0292"); }, url: "/system/tools", icon: Wrench },
      { id: "notify", get title() { return swt("interface.m1541"); }, url: "/system/notify", icon: BellRing },
      { id: "intercept", get title() { return swt("interface.m1239"); }, url: "/system/intercept", icon: ShieldAlert },
      { id: "asset-intercept", get title() { return swt("interface.m1166"); }, url: "/system/intercept/assets", icon: Ban },
      { id: "approvals", get title() { return swt("interface.m2145"); }, url: "/system/intercept/approvals", icon: ClipboardList },
      { id: "logs", get title() { return swt("interface.m2873"); }, url: "/system/logs", icon: ScrollText },
      { id: "settings", get title() { return swt("interface.m1644"); }, url: "/system/settings", icon: Settings2 },
    ],
  },
];
