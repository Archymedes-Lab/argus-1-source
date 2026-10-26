import LayoutGrid from "@lucide/svelte/icons/layout-grid";
import TriangleAlert from "@lucide/svelte/icons/triangle-alert";
import Activity from "@lucide/svelte/icons/activity";
import CircleCheck from "@lucide/svelte/icons/circle-check";
import MessageSquare from "@lucide/svelte/icons/message-square";
import Settings from "@lucide/svelte/icons/settings";
import type { View } from "./store.svelte";

export const NAV: { view: View; label: string; icon: typeof LayoutGrid }[] = [
  { view: "overview", label: "Overview", icon: LayoutGrid },
  { view: "findings", label: "Findings", icon: TriangleAlert },
  { view: "collectors", label: "Collectors", icon: Activity },
  { view: "review", label: "Review", icon: CircleCheck },
  { view: "assistant", label: "Assistant", icon: MessageSquare },
  { view: "settings", label: "Settings", icon: Settings },
];
