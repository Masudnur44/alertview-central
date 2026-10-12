import { useRouteContext } from "@tanstack/react-router";
import { can, type Permission } from "@/lib/permissions";

/** The signed-in user (available on every page under the signed-in layout). */
export function useMe() {
  return useRouteContext({ from: "/_authenticated" }).session.user;
}

/** Whether the signed-in user may do something. The server enforces this too; this only hides controls. */
export function useCan(perm: Permission): boolean {
  return can(useMe().roles, perm);
}
